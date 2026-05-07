package com.jadaptive.hsm.encrypt.hardware;

public interface HardwareKeyProvider {

	void init() throws Exception;

	byte[] encrypt(byte[] data) throws Exception;

	byte[] decrypt(byte[] data) throws Exception;

	boolean isAvailable();

	String getKeyId();
}
