package com.evimetry.aff4.encryption;

import com.evimetry.aff4.AFF4Lexicon;
import com.evimetry.aff4.rdf.RDFUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.jena.ext.xerces.impl.dv.util.Base64;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PrivateKeyWrappedKeyBag implements KeyBagItf {

	protected static final Logger logger = LoggerFactory.getLogger(PrivateKeyWrappedKeyBag.class);

	private String serialNumber;
	private String subjectName;
	private int keySizeBytes;
	private byte[] wrappedKey;
	private String id;

	public PrivateKeyWrappedKeyBag(String id, String subjectName, String serialNumber, int keySizeInBytes, byte[] wrappedKey) {
		this.id = id;
		this.subjectName = subjectName;
		this.serialNumber = serialNumber;
		this.keySizeBytes = keySizeInBytes;
		this.wrappedKey = wrappedKey;

	}

	public static PrivateKeyWrappedKeyBag loadFromResource(String resourceId, Model model) {

		Resource res = model.createResource(resourceId);

		if (res != null) {
			if (res.hasProperty(RDF.type, model.createProperty(AFF4Lexicon.certWrappedKeyBag.getValue()))) {
				Optional<Integer> keySizeBytes = RDFUtil.readIntProperty(model, resourceId, AFF4Lexicon.keySizeInBytes);
				Optional<String> wrappedKey = RDFUtil.readStringProperty(model, resourceId, AFF4Lexicon.wrappedKey);
				Optional<String> subjectName = RDFUtil.readStringProperty(model, resourceId, AFF4Lexicon.x509SubjectName);
				Optional<String> serialNumber = RDFUtil.readStringProperty(model, resourceId, AFF4Lexicon.serialNumber);

				try {
					byte[] wrtkHex = Hex.decodeHex(wrappedKey.get());

					return new PrivateKeyWrappedKeyBag(resourceId, subjectName.get(), serialNumber.get(), keySizeBytes.get(), wrtkHex);

				}
				catch (DecoderException dex) {
					logger.info("Failed to unwrap RSA wrapped key", dex);
					return null;
				}

			}
		}
		return null;
	}


	public String getSerialNumber() {
		return serialNumber;
	}

	public String getSubjectName() {
		return subjectName;
	}


	public int getKeySizeInBytes() {
		return keySizeBytes;
	}

	public String getWrappedKey() {
		return ByteUtil.bytesToHex(wrappedKey);
	}

	public String getResourceID() {
		return id;
	}

	/**
	 * key wrapping as defined in RFC 3394 http://www.ietf.org/rfc/rfc3394.txt TODO - this is not used , but don't remove since we may need it in the
	 * future TODO - when decide to create password encrypted AFF4-L
	 *
	 * @param publicKey
	 * @param vek
	 * @return
	 */

	public byte[] wrap(String publicKey, byte[] vek)
	{
		throw new UnsupportedOperationException("private key based wrapping has not been implemented yet");
	}


	/**
	 *  Password unwrapping
	 *
	 * @param base64PrivateKey
	 * @return
	 */
	public final byte[] unwrap(String base64PrivateKey)
	{

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");

			final PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(base64PrivateKey)));

			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			return cipher.doFinal(this.wrappedKey);

		}
		catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			logger.info("KeyBag unwrapping failed with error", e);
		}
		return null;
	}

	@Override
	public void initProperties(Map<AFF4Lexicon, Collection<Object>> properties) {
		properties.put(AFF4Lexicon.passwordWrappedKeyBag, Collections.singletonList(AFF4Lexicon.forValue(getResourceID())));
		properties.put(AFF4Lexicon.serialNumber, Collections.singletonList(AFF4Lexicon.forValue(String.valueOf(getSerialNumber()))));
		properties.put(AFF4Lexicon.keySizeInBytes, Collections.singletonList(AFF4Lexicon.forValue(String.valueOf(getKeySizeInBytes()))));
		properties.put(AFF4Lexicon.x509SubjectName, Collections.singletonList(AFF4Lexicon.forValue(getSubjectName())));
		properties.put(AFF4Lexicon.wrappedKey, Collections.singletonList(AFF4Lexicon.forValue(getWrappedKey())));
	}

}
