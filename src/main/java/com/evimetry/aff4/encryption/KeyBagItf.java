package com.evimetry.aff4.encryption;

import com.evimetry.aff4.AFF4Lexicon;
import org.apache.jena.rdf.model.Model;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Map;

public interface KeyBagItf {

	static PasswordWrappedKeyBag loadFromResource(String resourceId, Model model) {
		return null;
	}

	byte[] wrap(String password, byte[] vek);
	byte[] unwrap(String password);

	void initProperties(Map<AFF4Lexicon, Collection<Object>> properties);

}
