package com.jadaptive.hsm.encrypt.hardware;

import java.io.IOException;
import java.io.InputStream;
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

import com.jadaptive.hsm.crypto.SelfSignedCertificateGenerator;

public class Pkcs11HardwareKeyProvider implements HardwareKeyProvider {

	private final int keySize;
	private final String keyLabel;
	private final String configPath;
	private Provider provider;
	private KeyPair keyPair;

	public Pkcs11HardwareKeyProvider(int keySize, String keyLabel, String configPath) {
		this.keySize = keySize;
		this.keyLabel = keyLabel;
		this.configPath = configPath;
	}

	@Override
	public void init() throws Exception {
		Provider pkcs11Provider = createProvider();
		this.provider = pkcs11Provider;
		this.keyPair = loadOrCreateKeyPair(pkcs11Provider);
	}

	@Override
	public byte[] encrypt(byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", provider);
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		return cipher.doFinal(data);
	}

	@Override
	public byte[] decrypt(byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", provider);
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		return cipher.doFinal(data);
	}

	@Override
	public boolean isAvailable() {
		return provider != null;
	}

	@Override
	public String getKeyId() {
		return "pkcs11:" + keyLabel;
	}

	private Provider createProvider() throws IOException {
		Path path = Paths.get(configPath);
		if (!Files.exists(path)) {
			throw new IllegalArgumentException("PKCS#11 config file not found at " + path.toAbsolutePath());
		}

		try (InputStream input = Files.newInputStream(path)) {
			Provider pkcs11Provider = createSunPkcs11Provider(input);
			Security.addProvider(pkcs11Provider);
			return pkcs11Provider;
		}
	}

	private Provider createSunPkcs11Provider(InputStream input) {
		try {
			Class<?> clazz = Class.forName("sun.security.pkcs11.SunPKCS11");
			return (Provider) clazz.getConstructor(InputStream.class).newInstance(input);
		} catch (ReflectiveOperationException ex) {
			throw new IllegalArgumentException("SunPKCS11 provider not available on this runtime.", ex);
		}
	}

	private KeyPair loadOrCreateKeyPair(Provider pkcs11Provider) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
		keyStore.load(null, null);

		if (keyStore.containsAlias(keyLabel)) {
			Key key = keyStore.getKey(keyLabel, null);
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keyLabel);
			if (key == null || certificate == null) {
				throw new IllegalStateException("PKCS#11 key alias found but key or certificate missing.");
			}
			return new KeyPair(certificate.getPublicKey(), (java.security.PrivateKey) key);
		}

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", pkcs11Provider);
		generator.initialize(keySize);
		KeyPair generated = generator.generateKeyPair();
		X509Certificate cert = SelfSignedCertificateGenerator.generateSelfSignedCertificate(
				generated,
				"Jadaptive Hardware Encryption",
				"SHA256withRSA");
		keyStore.setKeyEntry(keyLabel, generated.getPrivate(), null, new X509Certificate[] { cert });
		return generated;
	}
}
