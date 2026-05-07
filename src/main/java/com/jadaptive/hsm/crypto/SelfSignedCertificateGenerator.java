package com.jadaptive.hsm.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public final class SelfSignedCertificateGenerator {

	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

	private SelfSignedCertificateGenerator() {
	}

	public static KeyPair generateRsaKeyPair(int keySize) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(keySize);
		return generator.generateKeyPair();
	}

	public static X509Certificate generateSelfSignedCertificate(KeyPair pair, String commonName,
			String signatureAlgorithm) throws Exception {
		ensureProvider();

		X500Name subject = new X500Name("CN=" + commonName);
		Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
		Date notAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 365 * 10L);
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				subject,
				serial,
				notBefore,
				notAfter,
				subject,
				pair.getPublic());

		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
				.setProvider(BC)
				.build(pair.getPrivate());
		X509CertificateHolder holder = builder.build(signer);
		return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
	}

	public static java.security.KeyStore createPkcs12Keystore(KeyPair pair, X509Certificate[] chain,
			String alias, char[] password) throws Exception {
		java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
		store.load(null);
		store.setKeyEntry(alias, pair.getPrivate(), password, chain);
		return store;
	}

	private static void ensureProvider() {
		if (Security.getProvider(BC) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}
}
