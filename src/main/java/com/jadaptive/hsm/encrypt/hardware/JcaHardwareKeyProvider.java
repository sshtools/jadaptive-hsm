package com.jadaptive.hsm.encrypt.hardware;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.jadaptive.hsm.crypto.SelfSignedCertificateGenerator;

public class JcaHardwareKeyProvider implements HardwareKeyProvider {

	private static final String KEYCHAIN_DISPLAY_LABEL = "Jadaptive Hardware Encryption";
	private static final String LEGACY_KEY_LABEL = "jadaptive-hsm-key";

	private final int keySize;
	private final String keyLabel;
	private final String providerName;
	private final String keystoreType;
	private final String keystorePath;
	private final String keystorePassword;
	private final boolean createIfMissing;
	private Provider provider;
	private KeyPair keyPair;

	public JcaHardwareKeyProvider(int keySize, String keyLabel, String providerName, String keystoreType,
			String keystorePath, String keystorePassword, boolean createIfMissing) {
		this.keySize = keySize;
		this.keyLabel = keyLabel;
		this.providerName = providerName;
		this.keystoreType = keystoreType == null || keystoreType.isBlank() ? "PKCS11" : keystoreType;
		this.keystorePath = keystorePath == null ? "" : keystorePath;
		this.keystorePassword = keystorePassword == null ? "" : keystorePassword;
		this.createIfMissing = createIfMissing;
	}

	@Override
	public void init() throws Exception {
		Provider resolved = Security.getProvider(providerName);
		if (resolved == null) {
			throw new IllegalArgumentException("JCA provider not available: " + providerName);
		}
		this.provider = resolved;
		this.keyPair = loadOrCreateKeyPair();
	}

	@Override
	public byte[] encrypt(byte[] data) throws Exception {
		Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		return cipher.doFinal(data);
	}

	@Override
	public byte[] decrypt(byte[] data) throws Exception {
		Cipher cipher = getCipher(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		return cipher.doFinal(data);
	}

	@Override
	public boolean isAvailable() {
		return provider != null;
	}

	@Override
	public String getKeyId() {
		return providerName + ":" + resolvePrimaryLabel();
	}

	private KeyPair loadOrCreateKeyPair() throws Exception {
		String primaryLabel = resolvePrimaryLabel();
		KeyStore keyStore = KeyStore.getInstance(keystoreType, provider);
		if (keystorePath.isBlank()) {
			keyStore.load(null, passwordChars());
		} else {
			Path path = Paths.get(keystorePath);
			if (!Files.exists(path)) {
				if (!createIfMissing) {
					throw new IllegalArgumentException("Keystore not found at " + path.toAbsolutePath());
				}
				Files.createDirectories(path.getParent());
				keyStore.load(null, passwordChars());
				try (OutputStream output = Files.newOutputStream(path)) {
					keyStore.store(output, passwordChars());
				}
			} else {
				try (InputStream input = Files.newInputStream(path)) {
					keyStore.load(input, passwordChars());
				}
			}
		}

		String existingLabel = findExistingLabel(keyStore, primaryLabel);
		if (existingLabel != null) {
			Key key = keyStore.getKey(existingLabel, keyEntryPassword(existingLabel));
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(existingLabel);
			if (key == null || certificate == null) {
				throw new IllegalStateException("Key alias found but key or certificate missing.");
			}
			return new KeyPair(certificate.getPublicKey(), (java.security.PrivateKey) key);
		}

		if (!createIfMissing) {
			throw new IllegalStateException("Key alias not found: " + primaryLabel);
		}

		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}

		KeyPairGenerator generator = getKeyPairGenerator();
		generator.initialize(keySize);
		KeyPair generated = generator.generateKeyPair();
		X509Certificate cert = SelfSignedCertificateGenerator.generateSelfSignedCertificate(
				generated,
				"Jadaptive Hardware Encryption",
				"SHA256withRSA");
		keyStore.setKeyEntry(primaryLabel, generated.getPrivate(), keyEntryPassword(primaryLabel), new X509Certificate[] { cert });

		if (!keystorePath.isBlank()) {
			try (OutputStream output = Files.newOutputStream(Paths.get(keystorePath))) {
				keyStore.store(output, passwordChars());
			}
		} else if (requiresSystemStoreCommit()) {
			keyStore.store(null, keyEntryPassword(primaryLabel));
		}
		return generated;
	}

	private KeyPairGenerator getKeyPairGenerator() throws Exception {
		try {
			return KeyPairGenerator.getInstance("RSA", provider);
		} catch (Exception ex) {
			return KeyPairGenerator.getInstance("RSA");
		}
	}

	private Cipher getCipher(int mode, java.security.Key key) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", provider);
			cipher.init(mode, key);
			return cipher;
		} catch (Exception ex) {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(mode, key);
			return cipher;
		}
	}

	private char[] passwordChars() {
		return keystorePassword.isBlank() ? null : keystorePassword.toCharArray();
	}

	private char[] keyEntryPassword(String label) {
		char[] password = passwordChars();
		if (password != null) {
			return password;
		}
		if (requiresSystemStoreCommit()) {
			return label.toCharArray();
		}
		return null;
	}

	private boolean requiresSystemStoreCommit() {
		return "KeychainStore".equalsIgnoreCase(keystoreType) || "Windows-MY".equalsIgnoreCase(keystoreType);
	}

	private String resolvePrimaryLabel() {
		if (isKeychainStore() && (keyLabel.isBlank() || LEGACY_KEY_LABEL.equals(keyLabel))) {
			return KEYCHAIN_DISPLAY_LABEL;
		}
		return keyLabel;
	}

	private String findExistingLabel(KeyStore keyStore, String primaryLabel) throws Exception {
		if (keyStore.containsAlias(primaryLabel)) {
			return primaryLabel;
		}
		if (isKeychainStore() && !LEGACY_KEY_LABEL.equals(primaryLabel) && keyStore.containsAlias(LEGACY_KEY_LABEL)) {
			return LEGACY_KEY_LABEL;
		}
		return null;
	}

	private boolean isKeychainStore() {
		return "KeychainStore".equalsIgnoreCase(keystoreType);
	}
}
