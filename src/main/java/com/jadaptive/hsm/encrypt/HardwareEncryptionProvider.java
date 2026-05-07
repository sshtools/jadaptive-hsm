package com.jadaptive.hsm.encrypt;

import com.jadaptive.hsm.encrypt.hardware.HardwareKeyProvider;
import com.jadaptive.hsm.encrypt.hardware.HardwareKeyProviderFactory;
public class HardwareEncryptionProvider extends BaseEnvelopeEncryptionProvider {

	private final boolean enabled;
	private final int keySize;
	private final String keyLabel;
	private final String pkcs11Config;
	private final String jcaProvider;
	private final String keystoreType;
	private final String keystorePath;
	private final String keystorePassword;
	private final boolean createIfMissing;
	private final String nativeBackend;
	private HardwareKeyProvider hardwareKeyProvider;

	public HardwareEncryptionProvider() {
		this(new Builder());
	}

	private HardwareEncryptionProvider(Builder builder) {
		this.enabled = builder.enabled;
		this.keySize = builder.keySize;
		this.keyLabel = builder.keyLabel;
		this.pkcs11Config = builder.pkcs11Config;
		this.jcaProvider = builder.jcaProvider;
		this.keystoreType = builder.keystoreType;
		this.keystorePath = builder.keystorePath;
		this.keystorePassword = builder.keystorePassword;
		this.createIfMissing = builder.createIfMissing;
		this.nativeBackend = builder.nativeBackend;
	}

	public static Builder builder() {
		return new Builder();
	}

	@Override
	public int priority() {
		return 10;
	}

	@Override
	public void init() throws Exception {
		if (!enabled) {
			throw new IllegalArgumentException("Hardware encryption disabled.");
		}

		HardwareKeyProvider provider = HardwareKeyProviderFactory.create(
				keySize,
				keyLabel,
				pkcs11Config,
				jcaProvider,
				keystoreType,
				keystorePath,
				keystorePassword,
				createIfMissing,
				nativeBackend);
		provider.init();
		this.hardwareKeyProvider = provider;
	}

	@Override
	protected byte[] encryptKey(byte[] key) throws Exception {
		return hardwareKeyProvider.encrypt(key);
	}

	@Override
	protected byte[] decryptKey(byte[] wrappedKey) throws Exception {
		return hardwareKeyProvider.decrypt(wrappedKey);
	}

	public String getHardwareKeyId() {
		return hardwareKeyProvider.getKeyId();
	}

	public byte[] exportMasterKey() {
		throw new UnsupportedOperationException("Hardware keys are non-exportable.");
	}

	public static class Builder {
		private boolean enabled = true;
		private int keySize = 2048;
		private String keyLabel = "jadaptive-hsm-key";
		private String pkcs11Config = "";
		private String jcaProvider = "";
		private String keystoreType = "";
		private String keystorePath = "";
		private String keystorePassword = "";
		private boolean createIfMissing = true;
		private String nativeBackend = "";

		public Builder setEnabled(boolean enabled) {
			this.enabled = enabled;
			return this;
		}

		public Builder setKeySize(int keySize) {
			this.keySize = keySize;
			return this;
		}

		public Builder setKeyLabel(String keyLabel) {
			this.keyLabel = keyLabel == null ? "" : keyLabel;
			return this;
		}

		public Builder setPkcs11Config(String pkcs11Config) {
			this.pkcs11Config = pkcs11Config == null ? "" : pkcs11Config;
			return this;
		}

		public Builder setJcaProvider(String jcaProvider) {
			this.jcaProvider = jcaProvider == null ? "" : jcaProvider;
			return this;
		}

		public Builder setKeystoreType(String keystoreType) {
			this.keystoreType = keystoreType == null ? "" : keystoreType;
			return this;
		}

		public Builder setKeystorePath(String keystorePath) {
			this.keystorePath = keystorePath == null ? "" : keystorePath;
			return this;
		}

		public Builder setKeystorePassword(String keystorePassword) {
			this.keystorePassword = keystorePassword == null ? "" : keystorePassword;
			return this;
		}

		public Builder setCreateIfMissing(boolean createIfMissing) {
			this.createIfMissing = createIfMissing;
			return this;
		}

		public Builder setNativeBackend(String nativeBackend) {
			this.nativeBackend = nativeBackend == null ? "" : nativeBackend;
			return this;
		}

		public HardwareEncryptionProvider build() {
			return new HardwareEncryptionProvider(this);
		}
	}
}
