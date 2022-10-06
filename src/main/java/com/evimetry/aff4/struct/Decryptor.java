package com.evimetry.aff4.struct;

import com.evimetry.aff4.encryption.Cipher;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Decryptor {

	private final byte[] key1;
	private final byte[] key2;

	public Decryptor(byte[] key1, byte[] key2){
		this.key1 = key1;
		this.key2 = key2;
	}

	public ByteBuffer decrypt(ByteBuffer input, long chunkId)
			  throws IOException
	{
		Cipher cipher = new Cipher(false, key1,key2);
		byte[] out = cipher.createOutBuffer();

		if(input.limit() != out.length ){
			throw new IOException("Wrong data unit size for decryption. allowed "+cipher.getDataUnitSize());
		}

		byte[] inputb = new byte[input.limit()];
		input.get(inputb);

		int res = cipher.doCipher(inputb, out,chunkId);
		if(res != input.limit()){
			throw new IOException("Wrong decryption buffer size"+cipher.getDataUnitSize());
		}

		return ByteBuffer.wrap(out);
	}

}
