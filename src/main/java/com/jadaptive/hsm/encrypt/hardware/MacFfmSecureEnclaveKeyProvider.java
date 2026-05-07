/*
 * Copyright © 2024 Jadaptive Limited (support@jadaptive.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.jadaptive.hsm.encrypt.hardware;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;

/**
 * macOS Secure Enclave key provider implemented using the Java 22 Foreign Function
 * &amp; Memory (FFM) API ({@code java.lang.foreign.*}).
 *
 * <p>This provider calls the macOS Security framework directly via the native
 * linker, without any JNA dependency. It mirrors the key management behaviour of
 * {@link MacSecureEnclaveKeyProvider} (the JNA version), which is retained
 * alongside this implementation.
 *
 * <p><strong>Requirements</strong>: Java 22+ at runtime (FFM is stable from Java 22).
 * If initialisation fails (e.g. no Secure Enclave hardware or missing keychain entitlement),
 * an exception is thrown and the caller ({@link HardwareKeyProviderFactory}) will log the
 * reason and fall back to an alternative provider.
 */
public class MacFfmSecureEnclaveKeyProvider implements HardwareKeyProvider {

    private static final String PROVIDER_TAG = "macos-ffm-secure-enclave";
    private static final String DEFAULT_LABEL = "Jadaptive Hardware Encryption";
    private static final String LEGACY_LABEL = "jadaptive-hsm-key";
    private static final int KEY_SIZE_BITS = 256;
    private static final int CF_NUMBER_INT_TYPE = 9; // kCFNumberIntType
    private static final int K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE = 1 << 2;
    private static final int ERR_SEC_SUCCESS = 0;

    // CoreFoundation encoding constant for UTF-8
    private static final int K_CF_STRING_ENCODING_UTF8 = 0x08000100;

    private final String keyLabel;
    private final byte[] applicationTag;

    // Native library handles (loaded lazily in init)
    private SymbolLookup securityLib;
    private SymbolLookup coreFoundationLib;
    private Linker linker;
    private Arena arena;

    // Cached key references (raw pointer addresses stored as longs)
    private long privateKeyAddr;
    private long publicKeyAddr;
    private boolean available;

    // Cached constant addresses (initialised once in init)
    private long secClassKeyAddr;
    private long secAttrKeyTypeAddr;
    private long secAttrKeyTypeECAddr;
    private long secAttrKeySizeAddr;
    private long secAttrTokenIdAddr;
    private long secAttrTokenIdSecureEnclaveAddr;
    private long secAttrIsPermanentAddr;
    private long secAttrApplicationTagAddr;
    private long secAttrLabelAddr;
    private long secAttrKeyClassAddr;
    private long secAttrKeyClassPrivateAddr;
    private long secReturnRefAddr;
    private long secMatchLimitAddr;
    private long secMatchLimitOneAddr;
    private long secAttrAccessibleAfterFirstUnlockAddr;
    private long secAttrAccessControlAddr;
    private long secKeyAlgEciesAddr;
    private long cfBooleanTrueAddr;
    private long secClassAddr;

    // Method handles
    private MethodHandle cfDictionaryCreateMutable;
    private MethodHandle cfDictionarySetValue;
    private MethodHandle cfRelease;
    private MethodHandle cfDataCreate;
    private MethodHandle cfDataGetLength;
    private MethodHandle cfDataGetBytePtr;
    private MethodHandle cfStringCreateWithCString;
    private MethodHandle cfNumberCreate;
    private MethodHandle cfCopyDescription;
    private MethodHandle cfStringGetLength;
    private MethodHandle cfStringGetMaximumSizeForEncoding;
    private MethodHandle cfStringGetCString;
    private MethodHandle cfAllocatorGetDefault;
    private MethodHandle secKeyCreateRandomKey;
    private MethodHandle secKeyCopyPublicKey;
    private MethodHandle secKeyCreateEncryptedData;
    private MethodHandle secKeyCreateDecryptedData;
    private MethodHandle secItemCopyMatching;
    private MethodHandle secAccessControlCreateWithFlags;

    public MacFfmSecureEnclaveKeyProvider(int keySize, String keyLabel) {
        // keySize is fixed at 256 for Secure Enclave EC keys; parameter ignored
        this.keyLabel = normalizeLabel(keyLabel);
        this.applicationTag = this.keyLabel.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void init() throws Exception {
        if (available) {
            return;
        }
        linker = Linker.nativeLinker();
        arena = Arena.ofShared();

        SymbolLookup stdlib = linker.defaultLookup();

        // Load Security and CoreFoundation frameworks.
        // On macOS these are Frameworks, not bare dylibs, so we must use the full path.
        securityLib = SymbolLookup.libraryLookup(
                "/System/Library/Frameworks/Security.framework/Security", arena);
        coreFoundationLib = SymbolLookup.libraryLookup(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", arena);

        resolveMethodHandles(stdlib);
        resolveConstants();

        privateKeyAddr = loadOrCreatePrivateKey();
        publicKeyAddr = secKeyCopyPublicKey(privateKeyAddr);
        if (publicKeyAddr == 0L) {
            throw new IllegalStateException(
                    "FFM: Failed to resolve public key from Secure Enclave private key.");
        }
        available = true;
    }

    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        long plain = cfDataCreate(data);
        long errorRef = 0L;
        long cipher = secKeyCreateEncryptedData(publicKeyAddr, secKeyAlgEciesAddr, plain, errorRef);
        cfRelease(plain);
        if (cipher == 0L) {
            throw new IllegalStateException("FFM: Failed to encrypt with Secure Enclave key.");
        }
        try {
            return cfDataToBytes(cipher);
        } finally {
            cfRelease(cipher);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        long cipher = cfDataCreate(data);
        long errorRef = 0L;
        long plain = secKeyCreateDecryptedData(privateKeyAddr, secKeyAlgEciesAddr, cipher, errorRef);
        cfRelease(cipher);
        if (plain == 0L) {
            throw new IllegalStateException("FFM: Failed to decrypt with Secure Enclave key.");
        }
        try {
            return cfDataToBytes(plain);
        } finally {
            cfRelease(plain);
        }
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    @Override
    public String getKeyId() {
        return PROVIDER_TAG + ":" + keyLabel;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Invokes a method handle, rethrowing any checked Throwable as an IllegalStateException. */
    @SuppressWarnings("unchecked")
    private static <T> T mh(MethodHandle handle, Object... args) throws Exception {
        try {
            return (T) handle.invokeWithArguments(args);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Exception e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("FFM native call failed", t);
        }
    }

    private void resolveMethodHandles(SymbolLookup stdlib) {
        // CFAllocatorGetDefault() -> CFAllocatorRef
        cfAllocatorGetDefault = linker.downcallHandle(
                coreFoundationLib.find("CFAllocatorGetDefault").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS));

        // CFDictionaryCreateMutable(allocator, capacity, keyCallBacks, valueCallBacks) -> CFMutableDictionaryRef
        cfDictionaryCreateMutable = linker.downcallHandle(
                coreFoundationLib.find("CFDictionaryCreateMutable").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // CFDictionarySetValue(dict, key, value)
        cfDictionarySetValue = linker.downcallHandle(
                coreFoundationLib.find("CFDictionarySetValue").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // CFRelease(cf)
        cfRelease = linker.downcallHandle(
                coreFoundationLib.find("CFRelease").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

        // CFDataCreate(allocator, bytes, length) -> CFDataRef
        cfDataCreate = linker.downcallHandle(
                coreFoundationLib.find("CFDataCreate").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

        // CFDataGetLength(data) -> CFIndex (long)
        cfDataGetLength = linker.downcallHandle(
                coreFoundationLib.find("CFDataGetLength").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        // CFDataGetBytePtr(data) -> const UInt8 *
        cfDataGetBytePtr = linker.downcallHandle(
                coreFoundationLib.find("CFDataGetBytePtr").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // CFStringCreateWithCString(allocator, cStr, encoding) -> CFStringRef
        cfStringCreateWithCString = linker.downcallHandle(
                coreFoundationLib.find("CFStringCreateWithCString").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        // CFNumberCreate(allocator, theType, valuePtr) -> CFNumberRef
        cfNumberCreate = linker.downcallHandle(
                coreFoundationLib.find("CFNumberCreate").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        // CFCopyDescription(cf) -> CFStringRef
        cfCopyDescription = linker.downcallHandle(
                coreFoundationLib.find("CFCopyDescription").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // CFStringGetLength(str) -> CFIndex
        cfStringGetLength = linker.downcallHandle(
                coreFoundationLib.find("CFStringGetLength").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        // CFStringGetMaximumSizeForEncoding(length, encoding) -> CFIndex
        cfStringGetMaximumSizeForEncoding = linker.downcallHandle(
                coreFoundationLib.find("CFStringGetMaximumSizeForEncoding").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG,
                        ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));

        // CFStringGetCString(str, buffer, bufferSize, encoding) -> Boolean
        cfStringGetCString = linker.downcallHandle(
                coreFoundationLib.find("CFStringGetCString").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_BYTE,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));

        // SecKeyCreateRandomKey(attributes, error) -> SecKeyRef
        secKeyCreateRandomKey = linker.downcallHandle(
                securityLib.find("SecKeyCreateRandomKey").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // SecKeyCopyPublicKey(key) -> SecKeyRef
        secKeyCopyPublicKey = linker.downcallHandle(
                securityLib.find("SecKeyCopyPublicKey").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // SecKeyCreateEncryptedData(key, algorithm, plaintext, error) -> CFDataRef
        secKeyCreateEncryptedData = linker.downcallHandle(
                securityLib.find("SecKeyCreateEncryptedData").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // SecKeyCreateDecryptedData(key, algorithm, ciphertext, error) -> CFDataRef
        secKeyCreateDecryptedData = linker.downcallHandle(
                securityLib.find("SecKeyCreateDecryptedData").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // SecItemCopyMatching(query, result) -> OSStatus (int)
        secItemCopyMatching = linker.downcallHandle(
                securityLib.find("SecItemCopyMatching").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // SecAccessControlCreateWithFlags(allocator, protection, flags, error) -> SecAccessControlRef
        secAccessControlCreateWithFlags = linker.downcallHandle(
                securityLib.find("SecAccessControlCreateWithFlags").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    }

    private void resolveConstants() {
        secClassAddr = readGlobalPointer(securityLib, "kSecClass");
        secClassKeyAddr = readGlobalPointer(securityLib, "kSecClassKey");
        secAttrKeyTypeAddr = readGlobalPointer(securityLib, "kSecAttrKeyType");
        secAttrKeyTypeECAddr = readGlobalPointer(securityLib, "kSecAttrKeyTypeECSECPrimeRandom");
        secAttrKeySizeAddr = readGlobalPointer(securityLib, "kSecAttrKeySizeInBits");
        secAttrTokenIdAddr = readGlobalPointer(securityLib, "kSecAttrTokenID");
        secAttrTokenIdSecureEnclaveAddr = readGlobalPointer(securityLib, "kSecAttrTokenIDSecureEnclave");
        secAttrIsPermanentAddr = readGlobalPointer(securityLib, "kSecAttrIsPermanent");
        secAttrApplicationTagAddr = readGlobalPointer(securityLib, "kSecAttrApplicationTag");
        secAttrLabelAddr = readGlobalPointer(securityLib, "kSecAttrLabel");
        secAttrKeyClassAddr = readGlobalPointer(securityLib, "kSecAttrKeyClass");
        secAttrKeyClassPrivateAddr = readGlobalPointer(securityLib, "kSecAttrKeyClassPrivate");
        secReturnRefAddr = readGlobalPointer(securityLib, "kSecReturnRef");
        secMatchLimitAddr = readGlobalPointer(securityLib, "kSecMatchLimit");
        secMatchLimitOneAddr = readGlobalPointer(securityLib, "kSecMatchLimitOne");
        secAttrAccessibleAfterFirstUnlockAddr = readGlobalPointer(
                securityLib, "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly");
        secAttrAccessControlAddr = readGlobalPointer(securityLib, "kSecAttrAccessControl");
        secKeyAlgEciesAddr = readGlobalPointer(
                securityLib, "kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM");
        cfBooleanTrueAddr = readGlobalPointer(coreFoundationLib, "kCFBooleanTrue");
    }

    /**
     * Reads the pointer stored at a global variable symbol.
     * Security framework constants are {@code CFStringRef} / {@code CFTypeRef} globals —
     * i.e. the symbol address IS the value we pass to CF APIs.
     *
     * <p>{@code SymbolLookup.find()} returns a <em>zero-size</em> segment (address only).
     * We must call {@code reinterpret(8)} before trying to read 8 bytes as an ADDRESS.
     */
    private long readGlobalPointer(SymbolLookup lookup, String symbol) {
        MemorySegment seg = lookup.find(symbol).orElseThrow(
                () -> new IllegalStateException("FFM: symbol not found: " + symbol));
        // Reinterpret to expose the 8 bytes at the symbol address so we can read the pointer.
        return seg.reinterpret(ValueLayout.ADDRESS.byteSize())
                  .get(ValueLayout.ADDRESS, 0)
                  .address();
    }

    private long getAllocator() throws Exception {
        MemorySegment alloc = mh(cfAllocatorGetDefault);
        return alloc.address();
    }

    private long cfDictionaryCreateMutableCall() throws Exception {
        MemorySegment alloc = MemorySegment.ofAddress(getAllocator());
        MemorySegment result = mh(cfDictionaryCreateMutable, alloc, 0L, MemorySegment.NULL, MemorySegment.NULL);
        return result.address();
    }

    private void cfDictionarySetValueCall(long dict, long key, long value) throws Exception {
        mh(cfDictionarySetValue,
                MemorySegment.ofAddress(dict),
                MemorySegment.ofAddress(key),
                MemorySegment.ofAddress(value));
    }

    private void cfRelease(long ref) {
        if (ref == 0L) return;
        try {
            mh(cfRelease, MemorySegment.ofAddress(ref));
        } catch (Exception t) {
            // best-effort release
        }
    }

    private long cfDataCreate(byte[] bytes) throws Exception {
        try (Arena tmp = Arena.ofConfined()) {
            MemorySegment buf = tmp.allocate(bytes.length);
            buf.asByteBuffer().put(bytes);
            MemorySegment result = mh(cfDataCreate,
                    MemorySegment.ofAddress(getAllocator()), buf, (long) bytes.length);
            return result.address();
        }
    }

    private byte[] cfDataToBytes(long dataRef) throws Exception {
        MemorySegment seg = MemorySegment.ofAddress(dataRef);
        Long length = mh(cfDataGetLength, seg);
        if (length == null || length <= 0) return new byte[0];
        MemorySegment ptr = mh(cfDataGetBytePtr, seg);
        return MemorySegment.ofAddress(ptr.address()).reinterpret(length).toArray(ValueLayout.JAVA_BYTE);
    }

    private long cfStringCreate(String value) throws Exception {
        try (Arena tmp = Arena.ofConfined()) {
            byte[] utf8 = (value + "\0").getBytes(StandardCharsets.UTF_8);
            MemorySegment buf = tmp.allocate(utf8.length);
            buf.asByteBuffer().put(utf8);
            MemorySegment result = mh(cfStringCreateWithCString,
                    MemorySegment.ofAddress(getAllocator()), buf, K_CF_STRING_ENCODING_UTF8);
            return result.address();
        }
    }

    private long cfNumberCreateInt(int value) throws Exception {
        try (Arena tmp = Arena.ofConfined()) {
            MemorySegment intSeg = tmp.allocate(ValueLayout.JAVA_INT);
            intSeg.set(ValueLayout.JAVA_INT, 0, value);
            MemorySegment result = mh(cfNumberCreate,
                    MemorySegment.ofAddress(getAllocator()), (long) CF_NUMBER_INT_TYPE, intSeg);
            return result.address();
        }
    }

    private long secKeyCopyPublicKey(long privateKey) throws Exception {
        MemorySegment result = mh(secKeyCopyPublicKey, MemorySegment.ofAddress(privateKey));
        return result.address();
    }

    private long secKeyCreateEncryptedData(long keyAddr, long algAddr, long plainAddr, long errorAddr)
            throws Exception {
        MemorySegment result = mh(secKeyCreateEncryptedData,
                MemorySegment.ofAddress(keyAddr),
                MemorySegment.ofAddress(algAddr),
                MemorySegment.ofAddress(plainAddr),
                errorAddr == 0L ? MemorySegment.NULL : MemorySegment.ofAddress(errorAddr));
        return result.address();
    }

    private long secKeyCreateDecryptedData(long keyAddr, long algAddr, long cipherAddr, long errorAddr)
            throws Exception {
        MemorySegment result = mh(secKeyCreateDecryptedData,
                MemorySegment.ofAddress(keyAddr),
                MemorySegment.ofAddress(algAddr),
                MemorySegment.ofAddress(cipherAddr),
                errorAddr == 0L ? MemorySegment.NULL : MemorySegment.ofAddress(errorAddr));
        return result.address();
    }

    private long loadOrCreatePrivateKey() throws Exception {
        long existing = findExistingKey();
        return existing != 0L ? existing : createKey();
    }

    private long findExistingKey() throws Exception {
        long dict = cfDictionaryCreateMutableCall();
        long tag = cfDataCreate(applicationTag);
        try (Arena tmp = Arena.ofConfined()) {
            MemorySegment resultPtr = tmp.allocate(ValueLayout.ADDRESS);
            cfDictionarySetValueCall(dict, secClassAddr, secClassKeyAddr);
            cfDictionarySetValueCall(dict, secAttrApplicationTagAddr, tag);
            cfDictionarySetValueCall(dict, secAttrKeyClassAddr, secAttrKeyClassPrivateAddr);
            cfDictionarySetValueCall(dict, secReturnRefAddr, cfBooleanTrueAddr);
            cfDictionarySetValueCall(dict, secMatchLimitAddr, secMatchLimitOneAddr);
            Integer status = mh(secItemCopyMatching,
                    MemorySegment.ofAddress(dict), resultPtr);
            if (status != null && status == ERR_SEC_SUCCESS) {
                return resultPtr.get(ValueLayout.ADDRESS, 0).address();
            }
            return 0L;
        } finally {
            cfRelease(tag);
            cfRelease(dict);
        }
    }

    private long createKey() throws Exception {
        long dict = cfDictionaryCreateMutableCall();
        long tag = cfDataCreate(applicationTag);
        long label = cfStringCreate(keyLabel);
        long keySize = cfNumberCreateInt(KEY_SIZE_BITS);
        long allocAddr = getAllocator();

        // SecAccessControlCreateWithFlags
        try (Arena tmp = Arena.ofConfined()) {
            MemorySegment errorSeg = tmp.allocate(ValueLayout.ADDRESS);
            MemorySegment access = mh(secAccessControlCreateWithFlags,
                    MemorySegment.ofAddress(allocAddr),
                    MemorySegment.ofAddress(secAttrAccessibleAfterFirstUnlockAddr),
                    (long) K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE,
                    errorSeg);
            if (access.address() == 0L) {
                throw new IllegalStateException("FFM: Failed to create access control for Secure Enclave key." + cfErrorDescription(errorSeg));
            }
            long accessAddr = access.address();
            try {
                cfDictionarySetValueCall(dict, secAttrKeyTypeAddr, secAttrKeyTypeECAddr);
                cfDictionarySetValueCall(dict, secAttrKeySizeAddr, keySize);
                cfDictionarySetValueCall(dict, secAttrTokenIdAddr, secAttrTokenIdSecureEnclaveAddr);
                cfDictionarySetValueCall(dict, secAttrIsPermanentAddr, cfBooleanTrueAddr);
                cfDictionarySetValueCall(dict, secAttrApplicationTagAddr, tag);
                cfDictionarySetValueCall(dict, secAttrLabelAddr, label);
                cfDictionarySetValueCall(dict, secAttrAccessControlAddr, accessAddr);

                MemorySegment errSeg = tmp.allocate(ValueLayout.ADDRESS);
                MemorySegment key = mh(secKeyCreateRandomKey,
                        MemorySegment.ofAddress(dict), errSeg);
                if (key.address() == 0L) {
                    throw new IllegalStateException(
                            "FFM: Failed to create Secure Enclave key." + cfErrorDescription(errSeg));
                }
                return key.address();
            } finally {
                cfRelease(accessAddr);
                cfRelease(tag);
                cfRelease(label);
                cfRelease(keySize);
                cfRelease(dict);
            }
        }
    }

    private String cfStringToJava(long cfStringRef) {
        if (cfStringRef == 0L) return "<null>";
        try {
            Long len = mh(cfStringGetLength, MemorySegment.ofAddress(cfStringRef));
            if (len == null || len <= 0) return "<empty>";
            Long maxLen = mh(cfStringGetMaximumSizeForEncoding, len, K_CF_STRING_ENCODING_UTF8);
            if (maxLen == null || maxLen <= 0) return "<cf-encoding-error>";
            long bufSize = maxLen + 1;
            try (Arena tmp = Arena.ofConfined()) {
                MemorySegment buf = tmp.allocate(bufSize);
                Byte ok = mh(cfStringGetCString,
                        MemorySegment.ofAddress(cfStringRef), buf, bufSize, K_CF_STRING_ENCODING_UTF8);
                if (ok == null || ok == 0) return "<cf-string-conversion-failed>";
                byte[] bytes = buf.toArray(ValueLayout.JAVA_BYTE);
                int nullPos = bytes.length;
                for (int i = 0; i < bytes.length; i++) {
                    if (bytes[i] == 0) { nullPos = i; break; }
                }
                return new String(bytes, 0, nullPos, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            return "<cf-string-error: " + e.getMessage() + ">";
        }
    }

    private String cfErrorDescription(MemorySegment errOutPtr) {
        try {
            long errRef = errOutPtr.get(ValueLayout.ADDRESS, 0).address();
            if (errRef == 0L) return "";
            MemorySegment descStr = mh(cfCopyDescription, MemorySegment.ofAddress(errRef));
            if (descStr == null || descStr.address() == 0L) return " (unknown error)";
            try {
                return " (" + cfStringToJava(descStr.address()) + ")";
            } finally {
                cfRelease(descStr.address());
                cfRelease(errRef);
            }
        } catch (Exception e) {
            return " (cf-error-read-failed)";
        }
    }

    private String normalizeLabel(String raw) {
        if (raw == null || raw.isBlank() || LEGACY_LABEL.equals(raw)) {
            return DEFAULT_LABEL;
        }
        return raw;
    }
}
