package com.jadaptive.hsm.encrypt.hardware;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import com.sun.jna.NativeLibrary;

public abstract class AbstractJnaHardwareKeyProvider implements HardwareKeyProvider {

	private final int keySize;
	private final String keyLabel;
	private KeyPair keyPair;
	private boolean available;

	protected AbstractJnaHardwareKeyProvider(int keySize, String keyLabel) {
		this.keySize = keySize;
		this.keyLabel = keyLabel;
	}

	protected abstract String[] getLibraryNames();

	protected abstract String getProviderName();

	@Override
	public void init() throws Exception {
		available = loadNativeLibrary();
		if (!available) {
			throw new IllegalArgumentException("Native hardware library not available for " + getProviderName() + ".");
		}
		keyPair = generateKeyPair();
	}

	@Override
	public byte[] encrypt(byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
		return cipher.doFinal(data);
	}

	@Override
	public byte[] decrypt(byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
		return cipher.doFinal(data);
	}

	@Override
	public boolean isAvailable() {
		return available;
	}

	@Override
	public String getKeyId() {
		return getProviderName() + ":" + keyLabel;
	}

	protected KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}

	protected PublicKey getPublicKey() {
		return keyPair.getPublic();
	}

	protected PrivateKey getPrivateKey() {
		return keyPair.getPrivate();
	}

	private boolean loadNativeLibrary() {
		for (String library : getLibraryNames()) {
			try {
				NativeLibrary.getInstance(library);
				return true;
			} catch (UnsatisfiedLinkError ex) {
				continue;
			}
		}
		return false;
	}
}
