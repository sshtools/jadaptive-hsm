package com.jadaptive.hsm.encrypt.hardware;

public class WindowsNcryptKeyProvider extends AbstractJnaHardwareKeyProvider {

	public WindowsNcryptKeyProvider(int keySize, String keyLabel) {
		super(keySize, keyLabel);
	}

	@Override
	protected String[] getLibraryNames() {
		return new String[] { "ncrypt" };
	}

	@Override
	protected String getProviderName() {
		return "windows-ncrypt";
	}
}
