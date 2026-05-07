package com.jadaptive.hsm.encrypt;

public interface HsmEncryptionProvider {

	int priority();

	void init() throws Exception;

	String encrypt(String value) throws Exception;

	String decrypt(String value) throws Exception;
}
