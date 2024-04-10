package com.evimetry.aff4.rdf;

import com.evimetry.aff4.AFF4Lexicon;

public class HashStruct {

	public final AFF4Lexicon lexiconType;
	public final String value;

	public HashStruct(AFF4Lexicon type,  String value){
		this.lexiconType = type;
		this.value = value;
	}


}
