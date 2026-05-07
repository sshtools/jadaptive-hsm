package com.jadaptive.hsm.encrypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.jadaptive.hsm.crypto.SelfSignedCertificateGenerator;
public class SoftwareEncryptionProvider extends BaseEnvelopeEncryptionProvider {
	private final boolean enabled;
	private final String keystoreDir;
	private final String keystoreSubdir;
	private final String keystoreFilename;
	private final String keystoreAlias;
	private final String keystorePassword;
	private final int keySize;
	private KeyPair keyPair;

	public SoftwareEncryptionProvider() {
		this(new Builder());
	}

	private SoftwareEncryptionProvider(Builder builder) {
		this.enabled = builder.enabled;
		this.keystoreDir = builder.keystoreDir;
		this.keystoreSubdir = builder.keystoreSubdir;
		this.keystoreFilename = builder.keystoreFilename;
		this.keystoreAlias = builder.keystoreAlias;
		this.keystorePassword = builder.keystorePassword;
		this.keySize = builder.keySize;
	}

	public static Builder builder() {
		return new Builder();
	}

	@Override
	public int priority() {
		return 100;
	}

	@Override
	public void init() throws Exception {
		if (!enabled) {
			throw new IllegalArgumentException("Software encryption disabled.");
		}

		Path baseFolder = Paths.get(keystoreDir).resolve(keystoreSubdir);
		Path keystorePath = baseFolder.resolve(keystoreFilename);
		String alias = keystoreAlias;
		char[] password = keystorePassword.toCharArray();

		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		if (Files.exists(keystorePath)) {
			try (InputStream input = Files.newInputStream(keystorePath)) {
				keystore.load(input, password);
			}
		} else {
			Files.createDirectories(baseFolder);
			KeyPair generated = SelfSignedCertificateGenerator.generateRsaKeyPair(keySize);
			X509Certificate cert = SelfSignedCertificateGenerator.generateSelfSignedCertificate(
					generated,
					"Jadaptive Software Encryption",
					"SHA256withRSA");
			keystore = SelfSignedCertificateGenerator.createPkcs12Keystore(generated, new X509Certificate[] { cert }, alias,
					password);
			try (OutputStream output = Files.newOutputStream(keystorePath)) {
				keystore.store(output, password);
			}
		}

		Key key = keystore.getKey(alias, password);
		if (key == null) {
			throw new IllegalStateException("Software encryption key missing from keystore.");
		}

		X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
		if (certificate == null) {
			throw new IllegalStateException("Software encryption certificate missing from keystore.");
		}

		keyPair = new KeyPair(certificate.getPublicKey(), (java.security.PrivateKey) key);
	}

	@Override
	protected byte[] encryptKey(byte[] key) throws Exception {
		var cipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keyPair.getPublic());
		return cipher.doFinal(key);
	}

	@Override
	protected byte[] decryptKey(byte[] wrappedKey) throws Exception {
		var cipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keyPair.getPrivate());
		return cipher.doFinal(wrappedKey);
	}

	public static class Builder {
		private boolean enabled = true;
		private String keystoreDir = "conf";
		private String keystoreSubdir = "private";
		private String keystoreFilename = "software-encryption.p12";
		private String keystoreAlias = "software-encryption";
		private String keystorePassword = "changeit";
		private int keySize = 2048;

		public Builder setEnabled(boolean enabled) {
			this.enabled = enabled;
			return this;
		}

		public Builder setKeystoreDir(String keystoreDir) {
			this.keystoreDir = keystoreDir == null ? "" : keystoreDir;
			return this;
		}

		public Builder setKeystoreSubdir(String keystoreSubdir) {
			this.keystoreSubdir = keystoreSubdir == null ? "" : keystoreSubdir;
			return this;
		}

		public Builder setKeystoreFilename(String keystoreFilename) {
			this.keystoreFilename = keystoreFilename == null ? "" : keystoreFilename;
			return this;
		}

		public Builder setKeystoreAlias(String keystoreAlias) {
			this.keystoreAlias = keystoreAlias == null ? "" : keystoreAlias;
			return this;
		}

		public Builder setKeystorePassword(String keystorePassword) {
			this.keystorePassword = keystorePassword == null ? "" : keystorePassword;
			return this;
		}

		public Builder setKeySize(int keySize) {
			this.keySize = keySize;
			return this;
		}

		public SoftwareEncryptionProvider build() {
			return new SoftwareEncryptionProvider(this);
		}
	}
}
