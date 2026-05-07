package com.jadaptive.hsm.encrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

public class HardwareEncryptionProviderTest {

	@Test
	public void hardwareKeyIsNonExportable() throws Exception {
		HardwareEncryptionProvider provider = new HardwareEncryptionProvider();
		try {
			provider.init();
		} catch (IllegalArgumentException ex) {
			Assumptions.assumeTrue(false, "Hardware provider not available: " + ex.getMessage());
			return;
		}

		assertThrows(UnsupportedOperationException.class, provider::exportMasterKey);
		String encrypted = provider.encrypt("hardware-secret");
		String decrypted = provider.decrypt(encrypted);
		assertEquals("hardware-secret", decrypted);
	}
}
