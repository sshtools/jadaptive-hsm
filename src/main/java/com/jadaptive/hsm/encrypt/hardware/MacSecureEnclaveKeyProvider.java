package com.jadaptive.hsm.encrypt.hardware;

import java.nio.charset.StandardCharsets;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.platform.mac.CoreFoundation;
import com.sun.jna.platform.mac.CoreFoundation.CFAllocatorRef;
import com.sun.jna.platform.mac.CoreFoundation.CFDataRef;
import com.sun.jna.platform.mac.CoreFoundation.CFDictionaryRef;
import com.sun.jna.platform.mac.CoreFoundation.CFMutableDictionaryRef;
import com.sun.jna.platform.mac.CoreFoundation.CFStringRef;
import com.sun.jna.platform.mac.CoreFoundation.CFTypeRef;

public class MacSecureEnclaveKeyProvider implements HardwareKeyProvider {

	private static final String PROVIDER_NAME = "macos-secure-enclave";
	private static final String DEFAULT_LABEL = "Jadaptive Hardware Encryption";
	private static final String LEGACY_LABEL = "jadaptive-hsm-key";
	private static final int KEY_SIZE_BITS = 256;
	private static final int CF_NUMBER_INT_TYPE = 9;
	private static final int K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE = 1 << 2;
	private static final int ERR_SEC_SUCCESS = 0;

	private final String keyLabel;
	private final byte[] applicationTag;
	private boolean available;
	private Pointer privateKeyRef;
	private Pointer publicKeyRef;

	public MacSecureEnclaveKeyProvider(int keySize, String keyLabel) {
		this.keyLabel = normalizeLabel(keyLabel);
		this.applicationTag = this.keyLabel.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public void init() throws Exception {
		available = loadSecurityFramework();
		if (!available) {
			throw new IllegalArgumentException("Security framework not available for " + PROVIDER_NAME + ".");
		}
		privateKeyRef = loadOrCreatePrivateKey();
		publicKeyRef = Security.INSTANCE.SecKeyCopyPublicKey(privateKeyRef);
		if (publicKeyRef == null) {
			throw new IllegalStateException("Failed to resolve public key from Secure Enclave key.");
		}
	}

	@Override
	public byte[] encrypt(byte[] data) throws Exception {
		CFDataRef plain = createCFData(data);
		PointerByReference error = new PointerByReference();
		Pointer cipher = Security.INSTANCE.SecKeyCreateEncryptedData(publicKeyRef, SEC_KEY_ALG_ECIES, plain, error);
		CoreFoundation.INSTANCE.CFRelease(plain);
		if (cipher == null) {
			throw buildError("Failed to encrypt with Secure Enclave key", error);
		}
		try {
			return toBytes(new CFDataRef(cipher));
		} finally {
			CoreFoundation.INSTANCE.CFRelease(new CFTypeRef(cipher));
		}
	}

	@Override
	public byte[] decrypt(byte[] data) throws Exception {
		CFDataRef cipher = createCFData(data);
		PointerByReference error = new PointerByReference();
		Pointer plain = Security.INSTANCE.SecKeyCreateDecryptedData(privateKeyRef, SEC_KEY_ALG_ECIES, cipher, error);
		CoreFoundation.INSTANCE.CFRelease(cipher);
		if (plain == null) {
			throw buildError("Failed to decrypt with Secure Enclave key", error);
		}
		try {
			return toBytes(new CFDataRef(plain));
		} finally {
			CoreFoundation.INSTANCE.CFRelease(new CFTypeRef(plain));
		}
	}

	@Override
	public boolean isAvailable() {
		return available;
	}

	@Override
	public String getKeyId() {
		return PROVIDER_NAME + ":" + keyLabel;
	}

	private Pointer loadOrCreatePrivateKey() throws Exception {
		Pointer existing = findExistingKey();
		if (existing != null) {
			return existing;
		}
		return createKey();
	}

	private Pointer findExistingKey() throws Exception {
		CFMutableDictionaryRef query = CoreFoundation.INSTANCE.CFDictionaryCreateMutable(
				CoreFoundation.INSTANCE.CFAllocatorGetDefault(),
				new CoreFoundation.CFIndex(0),
				Pointer.NULL,
				Pointer.NULL);
		CFDataRef tag = createCFData(applicationTag);
		try {
			CoreFoundation.INSTANCE.CFDictionarySetValue(query, SEC_CLASS, SEC_CLASS_KEY);
			CoreFoundation.INSTANCE.CFDictionarySetValue(query, SEC_ATTR_APPLICATION_TAG, tag);
			CoreFoundation.INSTANCE.CFDictionarySetValue(query, SEC_ATTR_KEY_CLASS, SEC_ATTR_KEY_CLASS_PRIVATE);
			CoreFoundation.INSTANCE.CFDictionarySetValue(query, SEC_RETURN_REF, CF_BOOLEAN_TRUE);
			CoreFoundation.INSTANCE.CFDictionarySetValue(query, SEC_MATCH_LIMIT, SEC_MATCH_LIMIT_ONE);

			PointerByReference result = new PointerByReference();
			int status = Security.INSTANCE.SecItemCopyMatching(query, result);
			if (status == ERR_SEC_SUCCESS) {
				return result.getValue();
			}
			return null;
		} finally {
			CoreFoundation.INSTANCE.CFRelease(tag);
			CoreFoundation.INSTANCE.CFRelease(query);
		}
	}

	private Pointer createKey() throws Exception {
		CFMutableDictionaryRef attributes = CoreFoundation.INSTANCE.CFDictionaryCreateMutable(
				CoreFoundation.INSTANCE.CFAllocatorGetDefault(),
				new CoreFoundation.CFIndex(0),
				Pointer.NULL,
				Pointer.NULL);
		CFDataRef tag = createCFData(applicationTag);
		CFStringRef label = createCFString(keyLabel);
		CFTypeRef keySize = createCFNumber(KEY_SIZE_BITS);
		PointerByReference error = new PointerByReference();
		Pointer access = Security.INSTANCE.SecAccessControlCreateWithFlags(
				CoreFoundation.INSTANCE.CFAllocatorGetDefault(),
				SEC_ATTR_ACCESSIBLE_AFTER_FIRST_UNLOCK_DEVICE_ONLY,
				K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE,
				error);
		if (access == null) {
			throw buildError("Failed to create access control", error);
		}
		try {
			CoreFoundation.INSTANCE.CFDictionarySetValue(attributes, SEC_ATTR_KEY_TYPE, SEC_ATTR_KEY_TYPE_EC);
			CoreFoundation.INSTANCE.CFDictionarySetValue(attributes, SEC_ATTR_KEY_SIZE, keySize);
			CoreFoundation.INSTANCE.CFDictionarySetValue(attributes, SEC_ATTR_TOKEN_ID, SEC_ATTR_TOKEN_ID_SECURE_ENCLAVE);
			CoreFoundation.INSTANCE.CFDictionarySetValue(attributes, SEC_ATTR_IS_PERMANENT, CF_BOOLEAN_TRUE);
			CoreFoundation.INSTANCE.CFDictionarySetValue(attributes, SEC_ATTR_APPLICATION_TAG, tag);
			CoreFoundation.INSTANCE.CFDictionarySetValue(attributes, SEC_ATTR_LABEL, label);
			CoreFoundation.INSTANCE.CFDictionarySetValue(attributes, SEC_ATTR_ACCESS_CONTROL, new CFTypeRef(access));

			Pointer key = Security.INSTANCE.SecKeyCreateRandomKey(attributes, error);
			if (key == null) {
				throw buildError("Failed to create Secure Enclave key", error);
			}
			return key;
		} finally {
			CoreFoundation.INSTANCE.CFRelease(new CFTypeRef(access));
			CoreFoundation.INSTANCE.CFRelease(tag);
			CoreFoundation.INSTANCE.CFRelease(label);
			CoreFoundation.INSTANCE.CFRelease(keySize);
			CoreFoundation.INSTANCE.CFRelease(attributes);
		}
	}

	private boolean loadSecurityFramework() {
		try {
			NativeLibrary.getInstance("Security");
			return true;
		} catch (UnsatisfiedLinkError ex) {
			return false;
		}
	}

	private RuntimeException buildError(String message, PointerByReference error) {
		String detail = "";
		Pointer ref = error != null ? error.getValue() : null;
		if (ref != null) {
			CFTypeRef errorRef = new CFTypeRef(ref);
			CFStringRef desc = CoreFoundation.INSTANCE.CFCopyDescription(errorRef);
			if (desc != null) {
				detail = " (" + toString(desc) + ")";
				CoreFoundation.INSTANCE.CFRelease(desc);
			}
			CoreFoundation.INSTANCE.CFRelease(errorRef);
		}
		return new IllegalStateException(message + detail);
	}

	private CFStringRef createCFString(String value) {
		char[] chars = value.toCharArray();
		return CoreFoundation.INSTANCE.CFStringCreateWithCharacters(
				CoreFoundation.INSTANCE.CFAllocatorGetDefault(),
				chars,
				new CoreFoundation.CFIndex(chars.length));
	}

	private CFDataRef createCFData(byte[] value) {
		Memory mem = new Memory(value.length);
		mem.write(0, value, 0, value.length);
		return CoreFoundation.INSTANCE.CFDataCreate(
				CoreFoundation.INSTANCE.CFAllocatorGetDefault(),
				mem,
				new CoreFoundation.CFIndex(value.length));
	}

	private CFTypeRef createCFNumber(int value) {
		IntByReference ref = new IntByReference(value);
		return CoreFoundation.INSTANCE.CFNumberCreate(
				CoreFoundation.INSTANCE.CFAllocatorGetDefault(),
				new CoreFoundation.CFIndex(CF_NUMBER_INT_TYPE),
				ref);
	}

	private byte[] toBytes(CFDataRef data) {
		int length = data != null ? CoreFoundation.INSTANCE.CFDataGetLength(data).intValue() : 0;
		if (length == 0) {
			return new byte[0];
		}
		Pointer ptr = CoreFoundation.INSTANCE.CFDataGetBytePtr(data);
		return ptr.getByteArray(0, length);
	}

	private String toString(CFStringRef cfString) {
		if (cfString == null) {
			return "";
		}
		int length = CoreFoundation.INSTANCE.CFStringGetLength(cfString).intValue();
		int maxSize = CoreFoundation.INSTANCE.CFStringGetMaximumSizeForEncoding(
				new CoreFoundation.CFIndex(length), CoreFoundation.kCFStringEncodingUTF8).intValue() + 1;
		Memory buffer = new Memory(maxSize);
		CoreFoundation.INSTANCE.CFStringGetCString(cfString, buffer, new CoreFoundation.CFIndex(maxSize), CoreFoundation.kCFStringEncodingUTF8);
		return buffer.getString(0);
	}

	private String normalizeLabel(String label) {
		if (label == null || label.isBlank() || LEGACY_LABEL.equals(label)) {
			return DEFAULT_LABEL;
		}
		return label;
	}

	private static CFStringRef cfStringConst(NativeLibrary lib, String symbol) {
		Pointer ptr = lib.getGlobalVariableAddress(symbol);
		return ptr == null ? null : new CFStringRef(ptr);
	}

	private static final NativeLibrary SECURITY_LIB = NativeLibrary.getInstance("Security");
	private static final NativeLibrary CORE_FOUNDATION_LIB = NativeLibrary.getInstance("CoreFoundation");

	private static final CFStringRef SEC_CLASS = cfStringConst(SECURITY_LIB, "kSecClass");
	private static final CFStringRef SEC_CLASS_KEY = cfStringConst(SECURITY_LIB, "kSecClassKey");
	private static final CFStringRef SEC_ATTR_KEY_TYPE = cfStringConst(SECURITY_LIB, "kSecAttrKeyType");
	private static final CFStringRef SEC_ATTR_KEY_TYPE_EC = cfStringConst(SECURITY_LIB, "kSecAttrKeyTypeECSECPrimeRandom");
	private static final CFStringRef SEC_ATTR_KEY_SIZE = cfStringConst(SECURITY_LIB, "kSecAttrKeySizeInBits");
	private static final CFStringRef SEC_ATTR_TOKEN_ID = cfStringConst(SECURITY_LIB, "kSecAttrTokenID");
	private static final CFStringRef SEC_ATTR_TOKEN_ID_SECURE_ENCLAVE = cfStringConst(SECURITY_LIB, "kSecAttrTokenIDSecureEnclave");
	private static final CFStringRef SEC_ATTR_IS_PERMANENT = cfStringConst(SECURITY_LIB, "kSecAttrIsPermanent");
	private static final CFStringRef SEC_ATTR_APPLICATION_TAG = cfStringConst(SECURITY_LIB, "kSecAttrApplicationTag");
	private static final CFStringRef SEC_ATTR_LABEL = cfStringConst(SECURITY_LIB, "kSecAttrLabel");
	private static final CFStringRef SEC_ATTR_KEY_CLASS = cfStringConst(SECURITY_LIB, "kSecAttrKeyClass");
	private static final CFStringRef SEC_ATTR_KEY_CLASS_PRIVATE = cfStringConst(SECURITY_LIB, "kSecAttrKeyClassPrivate");
	private static final CFStringRef SEC_RETURN_REF = cfStringConst(SECURITY_LIB, "kSecReturnRef");
	private static final CFStringRef SEC_MATCH_LIMIT = cfStringConst(SECURITY_LIB, "kSecMatchLimit");
	private static final CFStringRef SEC_MATCH_LIMIT_ONE = cfStringConst(SECURITY_LIB, "kSecMatchLimitOne");
	private static final CFStringRef SEC_ATTR_ACCESSIBLE_AFTER_FIRST_UNLOCK_DEVICE_ONLY = cfStringConst(
			SECURITY_LIB, "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly");
	private static final CFStringRef SEC_ATTR_ACCESS_CONTROL = cfStringConst(SECURITY_LIB, "kSecAttrAccessControl");
	private static final CFStringRef SEC_KEY_ALG_ECIES = cfStringConst(
			SECURITY_LIB, "kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM");

	private static final CFTypeRef CF_BOOLEAN_TRUE = new CFTypeRef(
			CORE_FOUNDATION_LIB.getGlobalVariableAddress("kCFBooleanTrue"));

	private interface Security extends com.sun.jna.Library {
		Security INSTANCE = Native.load("Security", Security.class);

		Pointer SecKeyCreateRandomKey(CFDictionaryRef parameters, PointerByReference error);

		Pointer SecKeyCopyPublicKey(Pointer key);

		Pointer SecKeyCreateEncryptedData(Pointer key, CFStringRef algorithm, CFDataRef plaintext, PointerByReference error);

		Pointer SecKeyCreateDecryptedData(Pointer key, CFStringRef algorithm, CFDataRef ciphertext, PointerByReference error);

		int SecItemCopyMatching(CFDictionaryRef query, PointerByReference result);

		Pointer SecAccessControlCreateWithFlags(CFAllocatorRef allocator, CFStringRef protection, int flags,
				PointerByReference error);
	}
}
