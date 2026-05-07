package com.jadaptive.hsm.encrypt.hardware;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang3.SystemUtils;

public final class HardwareKeyProviderFactory {

	private static final Logger log = Logger.getLogger(HardwareKeyProviderFactory.class.getName());

	private HardwareKeyProviderFactory() {
	}

	public static HardwareKeyProvider create(
			int keySize,
			String keyLabel,
			String pkcs11Config,
			String jcaProvider,
			String keystoreType,
			String keystorePath,
			String keystorePassword,
			boolean createIfMissing,
			String nativeBackend) {
		if (nativeBackend != null && !nativeBackend.isBlank()) {
			return createNativeProvider(keySize, keyLabel, nativeBackend, createIfMissing);
		}
		if (pkcs11Config != null && !pkcs11Config.isBlank()) {
			return new Pkcs11HardwareKeyProvider(keySize, keyLabel, pkcs11Config);
		}
		if (jcaProvider != null && !jcaProvider.isBlank()) {
			return new JcaHardwareKeyProvider(keySize, keyLabel, jcaProvider, keystoreType, keystorePath, keystorePassword,
					createIfMissing);
		}
		return createDefaultNativeProvider(keySize, keyLabel, createIfMissing);
	}

	private static HardwareKeyProvider createNativeProvider(int keySize, String keyLabel, String nativeBackend,
			boolean createIfMissing) {
		String backend = nativeBackend.trim().toLowerCase();
		switch (backend) {
		case "ffm-enclave":
		case "ffm":
			return new MacFfmSecureEnclaveKeyProvider(keySize, keyLabel);
		case "enclave":
		case "secure-enclave":
		case "secureenclave":
			return new MacSecureEnclaveKeyProvider(keySize, keyLabel);
		case "windows":
		case "cng":
			return new JcaHardwareKeyProvider(keySize, keyLabel, "SunMSCAPI", "Windows-MY", "", "", createIfMissing);
		case "mac":
		case "macos":
		case "security":
			return new JcaHardwareKeyProvider(keySize, keyLabel, "Apple", "KeychainStore", "", "", createIfMissing);
		default:
			throw new IllegalArgumentException("Unsupported native backend: " + nativeBackend);
		}
	}

	private static HardwareKeyProvider createDefaultNativeProvider(int keySize, String keyLabel, boolean createIfMissing) {
		if (SystemUtils.IS_OS_WINDOWS) {
			return new JcaHardwareKeyProvider(keySize, keyLabel, "SunMSCAPI", "Windows-MY", "", "", createIfMissing);
		}
		if (SystemUtils.IS_OS_MAC) {
			MacFfmSecureEnclaveKeyProvider ffm = new MacFfmSecureEnclaveKeyProvider(keySize, keyLabel);
			try {
				ffm.init();
				return ffm;
			} catch (Exception e) {
				log.log(Level.WARNING,
						"FFM Secure Enclave provider failed to initialise; falling back to Apple Keychain provider. Reason: " + e.getMessage(),
						e);
			}
			JcaHardwareKeyProvider keychain = new JcaHardwareKeyProvider(
					keySize, keyLabel, "Apple", "KeychainStore", "", "", createIfMissing);
			return keychain;
		}
		throw new IllegalArgumentException(
				"No hardware provider configured. Set hardware.pkcs11.config or hardware.jca.provider.");
	}
}