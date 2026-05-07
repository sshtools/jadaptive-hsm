package com.jadaptive.hsm.encrypt.hardware;

public class LinuxTpmPkcs11KeyProvider extends AbstractJnaHardwareKeyProvider {

	public LinuxTpmPkcs11KeyProvider(int keySize, String keyLabel) {
		super(keySize, keyLabel);
	}

	@Override
	protected String[] getLibraryNames() {
		return new String[] { "tpm2-pkcs11", "libtpm2_pkcs11.so", "libtpm2-pkcs11.so", "libtpm2-pkcs11.so.1" };
	}

	@Override
	protected String getProviderName() {
		return "linux-tpm2-pkcs11";
	}
}
