package com.jadaptive.hsm.encrypt;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class BaseEnvelopeEncryptionProvider implements HsmEncryptionProvider {

	private static final int GCM_IV_LENGTH = 12;
	private static final int GCM_TAG_LENGTH_BITS = 128;
	private final SecureRandom random = new SecureRandom();

	protected abstract byte[] encryptKey(byte[] key) throws Exception;

	protected abstract byte[] decryptKey(byte[] wrappedKey) throws Exception;

	@Override
	public String encrypt(String value) throws Exception {
		byte[] data = value.getBytes(StandardCharsets.UTF_8);
		byte[] rawKey = new byte[getKeyLengthBytes()];
		random.nextBytes(rawKey);

		byte[] iv = new byte[GCM_IV_LENGTH];
		random.nextBytes(iv);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawKey, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
		byte[] ciphertext = cipher.doFinal(data);

		byte[] wrappedKey = encryptKey(rawKey);
		if (wrappedKey.length > 0xFFFF) {
			throw new IllegalArgumentException("Wrapped key too large.");
		}

		// Envelope format: [wrappedKeyLen:2][ivLen:1][wrappedKey][iv][ciphertext]
		ByteBuffer buffer = ByteBuffer.allocate(2 + 1 + wrappedKey.length + iv.length + ciphertext.length);
		buffer.putShort((short) wrappedKey.length);
		buffer.put((byte) iv.length);
		buffer.put(wrappedKey);
		buffer.put(iv);
		buffer.put(ciphertext);

		return Base64.getEncoder().encodeToString(buffer.array());
	}

	@Override
	public String decrypt(String value) throws Exception {
		byte[] payload = Base64.getDecoder().decode(value);
		ByteBuffer buffer = ByteBuffer.wrap(payload);
		if (buffer.remaining() < 3) {
			throw new IllegalArgumentException("Invalid envelope payload.");
		}

		int wrappedKeyLength = Short.toUnsignedInt(buffer.getShort());
		int ivLength = Byte.toUnsignedInt(buffer.get());

		if (wrappedKeyLength <= 0 || ivLength <= 0) {
			throw new IllegalArgumentException("Invalid envelope lengths.");
		}
		if (buffer.remaining() < wrappedKeyLength + ivLength + 1) {
			throw new IllegalArgumentException("Incomplete envelope payload.");
		}

		byte[] wrappedKey = new byte[wrappedKeyLength];
		buffer.get(wrappedKey);
		byte[] iv = new byte[ivLength];
		buffer.get(iv);
		byte[] ciphertext = new byte[buffer.remaining()];
		buffer.get(ciphertext);

		byte[] rawKey = decryptKey(wrappedKey);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawKey, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
		byte[] plaintext = cipher.doFinal(ciphertext);
		return new String(plaintext, StandardCharsets.UTF_8);
	}

	private int getKeyLengthBytes() throws NoSuchAlgorithmException {
		return Math.min(Cipher.getMaxAllowedKeyLength("AES"), 256) / 8;
	}
}
