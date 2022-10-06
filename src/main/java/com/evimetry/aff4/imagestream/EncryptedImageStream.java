package com.evimetry.aff4.imagestream;

import com.evimetry.aff4.AFF4;
import com.evimetry.aff4.AFF4Lexicon;
import com.evimetry.aff4.codec.CompressionCodec;
import com.evimetry.aff4.container.AFF4ZipContainer;
import com.evimetry.aff4.encryption.KeyBagFactory;
import com.evimetry.aff4.encryption.KeyBagItf;
import com.evimetry.aff4.encryption.PasswordWrappedKeyBag;
import com.evimetry.aff4.rdf.RDFUtil;
import com.evimetry.aff4.struct.BevvyIndexLoaderFunction;
import com.evimetry.aff4.struct.ChunkLoaderFunction;
import com.evimetry.aff4.struct.Decryptor;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.jena.rdf.model.Model;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.Collections;

public class EncryptedImageStream extends AFF4ImageStream {

	/**
	 * The maximum number of bevvy index to keep in memory
	 */
	private final KeyBagItf keyBag;
	private final Decryptor decryptor;


	public EncryptedImageStream(String resource, AFF4ZipContainer parent, ZipFile zipContainer, SeekableByteChannel channel, Model model,
			  String password)
			  throws IOException
	{
		super(resource);
		this.parent = parent;
		this.size = RDFUtil.readLongProperty(model, resource, AFF4Lexicon.size).orElse(0l);
		this.chunkSize = RDFUtil.readIntProperty(model, resource, AFF4Lexicon.chunkSize).orElse(AFF4.DEFAULT_CHUNK_SIZE);
		this.chunksInSegment = RDFUtil.readIntProperty(model, resource, AFF4Lexicon.chunksInSegment).orElse(AFF4.DEFAULT_CHUNKS_PER_SEGMENT);

		String keyBagRes = RDFUtil.readResourceProperty(model, resource, AFF4Lexicon.KeyBag).orElse(null);


		if (keyBagRes != null) {

			keyBag = KeyBagFactory.getKeyBag(keyBagRes, model);

			if(keyBag == null ){
				throw new IOException("Cannot load KeyBag for encrypted stream " + resource);
			}

		}
		else {
			throw new IOException("No KeyBag found for resource " + resource);
		}

		try {

			byte[] derivedPassword = keyBag.unwrap(password);

			if (derivedPassword == null) {
				throw new IOException("Problem unwrapping derived password");
			}

			byte[] password1 = new byte[derivedPassword.length / 2];
			byte[] password2 = new byte[derivedPassword.length / 2];

			System.arraycopy(derivedPassword, 0, password1, 0, password1.length);
			System.arraycopy(derivedPassword, derivedPassword.length / 2, password2, 0, password2.length);
			decryptor = new Decryptor(password1, password2);


		}
		catch (Exception e) {
			throw new IOException(e);
		}

		String compression = RDFUtil.readResourceProperty(model, resource, AFF4Lexicon.compressionMethod).orElse(AFF4Lexicon.NoCompression.getValue());

		this.codec = CompressionCodec.getCodec(compression, chunkSize);
		this.bevvyCache = Caffeine.newBuilder().maximumSize(BEVVY_CACHE_SIZE).build();
		this.chunkCache = Caffeine.newBuilder().maximumSize((int) (CHUNK_CACHE_SIZE / (long) chunkSize)).build();
		this.bevvyLoader = new BevvyIndexLoaderFunction(resource, parent, zipContainer);
		this.chunkLoader = new ChunkLoaderFunction(parent, channel, bevvyCache, bevvyLoader, chunkSize, chunksInSegment, size(), codec, decryptor);
		initProperties();

	}

	private void initProperties() {

		properties.put(AFF4Lexicon.RDFType, Collections.singletonList(AFF4Lexicon.EncryptedStream));
		properties.put(AFF4Lexicon.size, Collections.singletonList(size));
		properties.put(AFF4Lexicon.chunkSize, Collections.singletonList(chunkSize));
		properties.put(AFF4Lexicon.chunksInSegment, Collections.singletonList(chunksInSegment));
		properties.put(AFF4Lexicon.compressionMethod, Collections.singletonList(AFF4Lexicon.forValue(codec.getResourceID())));
		keyBag.initProperties(properties);


	}
}
