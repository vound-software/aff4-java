package com.evimetry.aff4.encryption;

import com.evimetry.aff4.AFF4Lexicon;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;

public class KeyBagFactory {

	public static KeyBagItf getKeyBag(String resourceId, Model model){

		Resource res = model.createResource(resourceId);

		if (res != null) {
			if (res.hasProperty(RDF.type, model.createProperty(AFF4Lexicon.passwordWrappedKeyBag.getValue()))) {
				return PasswordWrappedKeyBag.loadFromResource(resourceId, model);
			}
			else if (res.hasProperty(RDF.type, model.createProperty(AFF4Lexicon.certWrappedKeyBag.getValue()))) {
				return PrivateKeyWrappedKeyBag.loadFromResource(resourceId, model);
			}
		}
		return null;
	}

}
