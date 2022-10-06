/*
 * Copyright (c) 2015-2016, Sebastian Deiss
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.evimetry.aff4.encryption;


import org.bouncycastle.crypto.BlockCipher;

import java.util.Arrays;

/**
 * XTS mode implementation.
 * <p>
 * XTS stands for XEX with tweak and ciphertext stealing. XTS is defined in the IEEE P1619(TM)/D16 Standard for Cryptographic Protection of Data on
 * Block-Oriented Storage Devices.
 *
 * @author Sebastian Deiss
 */
public final class XTS {

	private static final int XTS_DATA_UNIT_SIZE = 512;
	// Size of a 64 bit integer in bytes
	private static final int SIZE_OF_LONG = 8;
	// The block size of the underlying cipher
	private static int BLOCK_SIZE;
	private final BlockCipher tweakCipherInstance;
	private BlockCipher cipherInstance;

	/**
	 * Create a new XTS instance.
	 *
	 * @param cipher      The {@link BlockCipher } to use for encryption / decryption.
	 * @param tweakCipher The {@link BlockCipher } to use for tweak encryption.
	 * @throws IllegalStateException If both {@link BlockCipher } objects are not from the same algorithm.
	 */
	public XTS(final BlockCipher cipher, final BlockCipher tweakCipher)
			  throws IllegalStateException
	{
		if (!cipher.getAlgorithmName().equals(tweakCipher.getAlgorithmName()))
			throw new IllegalStateException();

		this.cipherInstance = cipher;
		this.tweakCipherInstance = tweakCipher;
		BLOCK_SIZE = cipher.getBlockSize();
	}

	/**
	 * Encrypt / decrypt a data unit in XTS mode.
	 *
	 * @param in             The input data unit.
	 * @param inOffset       Offset in the input data unit array.
	 * @param out            The output data unit.
	 * @param outOffset      Offset in the output data unit array.
	 * @param dataUnitNumber The sector number of this data unit on the block storage device.
	 * @return Returns the number of bytes processed.
	 */
	public int processDataUnit(byte[] in, final int inOffset, byte[] out, final int outOffset, final long dataUnitNumber)
			  throws IllegalStateException
	{
		int processedBytes = in.length - inOffset;
		// Check if the length of in is a multiple of BLOCK_SIZE
		if (processedBytes % BLOCK_SIZE != 0)
			throw new IllegalStateException();

		// Produce the tweak value
		byte[] tweak = new byte[BLOCK_SIZE];
		// Convert the dataUnitNumber (long) to little-endian bytes
		ByteUtil.storeInt64LE(dataUnitNumber, tweak, 0);
		// A long consists of 8 bytes but the block size is 16 so we
		// fill the rest of the IV array with zeros.
		Arrays.fill(tweak, SIZE_OF_LONG, BLOCK_SIZE, (byte) 0);
		// Encrypt tweak
		this.tweakCipherInstance.processBlock(tweak, 0, tweak, 0);

		for (int i = 0; i < XTS_DATA_UNIT_SIZE; i += BLOCK_SIZE) {
			// Encrypt / decrypt one block
			this.processBlock(in, inOffset + i, out, outOffset + i, tweak);
			// Multiply tweak by alpha
			tweak = this.multiplyTweakByA(tweak);
		}

		return processedBytes;
	}

	/**
	 * Gets the name of the underlying cipher.
	 *
	 * @return The name of the underlying cipher.
	 */
	public String getAlgorithmName()
	{
		return this.cipherInstance.getAlgorithmName();
	}

	/**
	 * Gets the size of an XTS data unit.
	 *
	 * @return The size of an XTS data unit.
	 */
	public final int getDataUnitSize()
	{
		return XTS_DATA_UNIT_SIZE;
	}

	/**
	 * Gets the block size of the underlying cipher which is equal to the XTS block size.
	 *
	 * @return The block size of the underlying cipher.
	 */
	public final int getBlockSize()
	{
		return BLOCK_SIZE;
	}

	/**
	 * Resets the cipher.
	 *
	 * @param cipher The new cipher to use or the old cipher but with other parameters.
	 */
	public void resetCipher(final BlockCipher cipher)
	{
		this.cipherInstance = cipher;
	}

	/**
	 * Encrypt / decrypt a single block in XTS mode.
	 *
	 * @param in        The input block.
	 * @param inOffset  Offset in the input block array.
	 * @param out       The output block.
	 * @param outOffset Offset in the output block array.
	 * @param tweak     The tweak value for this block.
	 * @return Returns the number of bytes processed.
	 */
	private int processBlock(byte[] in, final int inOffset, byte[] out, final int outOffset, final byte[] tweak)
	{
		// XOR
		// PP <- P ^ T
		for (int i = 0; i < BLOCK_SIZE; i++)
			in[inOffset + i] ^= tweak[i];

		// Encrypt	  CC <- enc(Key1, PP)
		// Or decrypt PP <- dec(Key1, CC)
		this.cipherInstance.processBlock(in, inOffset, out, outOffset);

		// XOR
		// C <- CC ^ T
		for (int i = 0; i < BLOCK_SIZE; i++)
			out[outOffset + i] ^= tweak[i];

		return BLOCK_SIZE;
	}

	/**
	 * Multiplication of two polynomials over the binary field GF(2) modulo x^128 + x^7 + x^2 + x + 1, where GF stands for Galois Field.
	 *
	 * @param tweak The tweak value which is a primitive element of GF(2^128)
	 * @return Returns the result of the multiplication as a byte array
	 */
	private byte[] multiplyTweakByA(final byte[] tweak)
	{
		long whiteningLo = ByteUtil.loadInt64LE(tweak, 0);
		long whiteningHi = ByteUtil.loadInt64LE(tweak, SIZE_OF_LONG);

		int finalCarry = 0 == (whiteningHi & 0x8000000000000000L) ? 0 : 135;

		whiteningHi <<= 1;
		whiteningHi |= whiteningLo >>> 63;
		whiteningLo <<= 1;
		whiteningLo ^= finalCarry;

		ByteUtil.storeInt64LE(whiteningLo, tweak, 0);
		ByteUtil.storeInt64LE(whiteningHi, tweak, SIZE_OF_LONG);

		return tweak;
	}

	//	public static void main(String[] args)
	//	{
	//		// IEEE 1619 test vector 10
	//		final String key = "2718281828459045235360287471352662497757247093699959574966967627";
	//		final String tweakKey = "3141592653589793238462643383279502884197169399375105820974944592";
	//		final String dataUnit = "00000000000000ff";
	//		final String plainText = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	//				  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	//				  + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	//				  + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
	//				  + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	//				  + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	//				  + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	//				  + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	//				  + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	//				  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	//				  + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	//				  + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
	//				  + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	//				  + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	//				  + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	//				  + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
	//		final String cipherText = "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
	//				  + "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
	//				  + "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
	//				  + "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
	//				  + "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
	//				  + "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
	//				  + "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
	//				  + "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
	//				  + "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
	//				  + "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
	//				  + "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
	//				  + "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
	//				  + "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
	//				  + "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
	//				  + "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
	//				  + "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151";
	//
	//		/*
	//		 * Run test with IEEE 1619 test vector 10
	//		 */
	//
	//		// Setup ciphers
	//		CipherParameters params = new KeyParameter(ByteUtil.hexToBytes(key));
	//		CipherParameters tweakParams = new KeyParameter(ByteUtil.hexToBytes(tweakKey));
	//		BlockCipher cipher = new AESEngine();
	//		BlockCipher tweakCipher = new AESEngine();
	//		cipher.init(true, params);
	//		tweakCipher.init(true, tweakParams);
	//
	//		// Setup XTS mode test
	//		XTS xts = new XTS(cipher, tweakCipher);
	//		byte[] plaintext = ByteUtil.hexToBytes(plainText);
	//		byte[] ciphertext = ByteUtil.hexToBytes(cipherText);
	//		long dataUnitNumber = ByteUtil.loadInt64BE(ByteUtil.hexToBytes(dataUnit), 0);
	//		byte[] createdCipherText = new byte[xts.getDataUnitSize()];
	//		byte[] decryptedPlainText = new byte[xts.getDataUnitSize()];
	//
	//		info();
	//		System.out.println("====================================================");
	//		System.out.println("IEEE 1619 test vector 10");
	//		System.out.println("Key               " + key);
	//		System.out.println("Tweak key:        " + tweakKey);
	//		System.out.println("Data unit number: " + dataUnitNumber);
	//		System.out.println("Plaintext:        " + plainText);
	//		System.out.println("Ciphertext:       " + cipherText);
	//		System.out.println("====================================================");
	//		System.out.println("Result");
	//		System.out.println("====================================================");
	//
	//		// Encrypt
	//		xts.processDataUnit(plaintext, 0, createdCipherText, 0, dataUnitNumber);
	//
	//		System.out.println("Ciphertext:       " + ByteUtil.bytesToHex(createdCipherText));
	//		if (ByteUtil.bytesToHex(createdCipherText).equals(cipherText))
	//			System.out.println("Ciphertext matches IEEE 1619 test vector 10");
	//		else
	//			System.out.println("Ciphertext does not match IEEE 1619 test vector 10");
	//
	//		// Decrypt
	//		cipher.init(false, params);
	//		xts.resetCipher(cipher);
	//		xts.processDataUnit(ciphertext, 0, decryptedPlainText, 0, dataUnitNumber);
	//
	//		System.out.println("Plaintext:        " + ByteUtil.bytesToHex(decryptedPlainText));
	//		if (ByteUtil.bytesToHex(decryptedPlainText).equals(plainText))
	//			System.out.println("Plaintext matches IEEE 1619 test vector 10");
	//		else
	//			System.out.println("Plaintext does not match IEEE 1619 test vector 10");
	//	}
	//
	//	private static void info()
	//	{
	//		System.out.println("XTS mode implementation for Java");
	//		System.out.println("specified in IEEE P1619(TM)/D16 Standard for");
	//		System.out.println("Cryptographic Protection of Data on Block-Oriented Storage Devices");
	//		System.out.println("Copyright (C) 2015-2016 Sebastian Deiss. All rights reserved.");
	//		System.out.println("");
	//	}


}
