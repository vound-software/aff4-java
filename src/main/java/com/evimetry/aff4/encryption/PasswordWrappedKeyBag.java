package com.evimetry.aff4.encryption;

import com.evimetry.aff4.AFF4Lexicon;
import com.evimetry.aff4.rdf.RDFUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordWrappedKeyBag implements KeyBagItf {

	protected static final Logger logger = LoggerFactory.getLogger(PasswordWrappedKeyBag.class);

	private static final byte[] default_iv = {(byte) 0xa6, (byte) 0xa6, (byte) 0xa6, (byte) 0xa6, (byte) 0xa6, (byte) 0xa6, (byte) 0xa6, (byte) 0xa6};


	private byte[] salt;
	private int iterations;
	private int keySizeBytes;
	private byte[] wrappedKey;
	private String id;

	public PasswordWrappedKeyBag(String id, byte[] salt, int iterations, int keySizeInBytes, byte[] wrappedKey) {
		this.id = id;
		this.salt = salt;
		this.iterations = iterations;
		this.keySizeBytes = keySizeInBytes;
		this.wrappedKey = wrappedKey;

	}

	public static PasswordWrappedKeyBag loadFromResource(String resourceId, Model model) {

		Resource res = model.createResource(resourceId);

		if (res != null) {
			if (res.hasProperty(RDF.type, model.createProperty(AFF4Lexicon.passwordWrappedKeyBag.getValue()))) {

				Optional<String> salt = RDFUtil.readStringProperty(model, resourceId, AFF4Lexicon.salt);
				Optional<Integer> iterations = RDFUtil.readIntProperty(model, resourceId, AFF4Lexicon.iterations);
				Optional<Integer> keySizeBytes = RDFUtil.readIntProperty(model, resourceId, AFF4Lexicon.keySizeInBytes);
				Optional<String> wrappedKey = RDFUtil.readStringProperty(model, resourceId, AFF4Lexicon.wrappedKey);

				try {

					byte[] saltHex = Hex.decodeHex(salt.get());
					byte[] wrtkHex = Hex.decodeHex(wrappedKey.get());

					return new PasswordWrappedKeyBag(resourceId, saltHex, iterations.get(), keySizeBytes.get(), wrtkHex);

				}
				catch (DecoderException dex) {
					logger.info("Failed to decode password wrapped KeyBag",dex);
					return null;
				}
			}
		}
		return null;
	}

	public String getSalt() {
		return ByteUtil.bytesToHex(salt);
	}

	public int getIterations() {
		return iterations;
	}

	public int getKeySizeInBytes() {
		return keySizeBytes;
	}

	public String getWrappedKey() {
		return ByteUtil.bytesToHex(wrappedKey);
	}

	/**
	 * key wrapping as defined in RFC 3394 http://www.ietf.org/rfc/rfc3394.txt TODO - this is not used , but don't remove since we may need it in the
	 * future TODO - when decide to create password encrypted AFF4-L
	 *
	 * @param password
	 * @return
	 */

	public byte[] wrap(String password, byte[] vek)
	{
		try {
			if (vek == null) {
				vek = SecureRandom.getSeed(keySizeBytes);
			}

			KeyParameter kp = null;
			kp = createDerivedKey(password);


			AESWrapEngine engine = new AESWrapEngine();

			ParametersWithIV cpar = new ParametersWithIV(kp, default_iv);

			engine.init(true, cpar);

			this.wrappedKey = engine.wrap(vek, 0, vek.length);

			return wrappedKey;
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			logger.info("Failed to wrap password wrapped KeyBag", e);
		}
		return null;
	}


	/**
	 *  Password unwrapping
	 *
	 * @param password
	 * @return
	 */
	public byte[] unwrap(String password)
	{
		try {
			KeyParameter kp = createDerivedKey(password);

			AESWrapEngine engine = new AESWrapEngine();

			ParametersWithIV cpar = new ParametersWithIV(kp, default_iv);

			engine.init(false, cpar);

			return engine.unwrap(wrappedKey, 0, wrappedKey.length);
		}
		catch (InvalidCipherTextException | NoSuchAlgorithmException | InvalidKeySpecException  e) {
			logger.info("Failed to unwrap password wrapped KeyBag", e);
		}
		return null;
	}

	@Override
	public void initProperties(Map<AFF4Lexicon, Collection<Object>> properties) {
		properties.put(AFF4Lexicon.passwordWrappedKeyBag, Collections.singletonList(AFF4Lexicon.forValue(getResourceID())));
		properties.put(AFF4Lexicon.iterations, Collections.singletonList(AFF4Lexicon.forValue(String.valueOf(getIterations()))));
		properties.put(AFF4Lexicon.keySizeInBytes, Collections.singletonList(AFF4Lexicon.forValue(String.valueOf(getKeySizeInBytes()))));
		properties.put(AFF4Lexicon.salt, Collections.singletonList(AFF4Lexicon.forValue(getSalt())));
		properties.put(AFF4Lexicon.wrappedKey, Collections.singletonList(AFF4Lexicon.forValue(getWrappedKey())));
	}

	/**
	 * Create derived key out of user provided key
	 *
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @return
	 */
	private KeyParameter createDerivedKey(String password)
			  throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySizeBytes * 8);

		SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

		byte[] derived = f.generateSecret(spec).getEncoded();

		KeyParameter kp = new KeyParameter(derived);
		return kp;
	}

	public String getResourceID() {
		return this.id;
	}

}
