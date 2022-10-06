/*
  This file is part of AFF4 Java.

  AFF4 Java is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  AFF4 Java is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with AFF4 Java.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.evimetry.aff4.struct;

import com.evimetry.aff4.IAFF4ImageStream;
import com.evimetry.aff4.codec.CompressionCodec;
import com.evimetry.aff4.container.AFF4ZipContainer;
import com.github.benmanes.caffeine.cache.Cache;
import org.apache.commons.compress.archivers.zip.ZipMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.util.function.Function;

/**
 * Function for loading a Chunk into memory for the given offset.
 */
public class ChunkLoaderFunction implements Function<Long, ByteBuffer> {

	private final static Logger logger = LoggerFactory.getLogger(ChunkLoaderFunction.class);
	/**
	 * The parent container
	 */
	@SuppressWarnings("unused")
	private final AFF4ZipContainer parent;
	/**
	 * The channel to load our buffer from
	 */
	private final SeekableByteChannel channel;
	/**
	 * The bevvy cache
	 */
	private final Cache<Integer, BevvyIndex> bevvyCache;
	/**
	 * Loader function for the cache.
	 */
	private final BevvyIndexLoaderFunction bevvyLoader;
	/**
	 * The chunksize
	 */
	private final long chunkSize;

	/**
	 * The total size og element
	 * Ths is introduced because axiom does not compress binary entries even if it marks them as compressed. and stores them in one chunk
	 */
	private final long totalSize;
	/**
	 * The number of chunks per segment
	 */
	private final long chunksInSegment;
	/**
	 * The compression codec to decompress raw buffers.
	 */
	private final CompressionCodec codec;


	private final Decryptor decryptor;

	/**
	 * Function for loading a Chunk into memory for the given offset.
	 *
	 * @param parent
	 * @param channel
	 * @param bevvyCache
	 * @param bevvyLoader
	 * @param chunkSize
	 * @param chunksInSegment
	 * @param codec
	 * @param decryptor
	 */
	public ChunkLoaderFunction(AFF4ZipContainer parent, SeekableByteChannel channel, Cache<Integer, BevvyIndex> bevvyCache,
			  BevvyIndexLoaderFunction bevvyLoader, int chunkSize, int chunksInSegment,long totalSize, CompressionCodec codec, Decryptor decryptor)
	{
		this.parent = parent;
		this.channel = channel;
		this.bevvyCache = bevvyCache;
		this.bevvyLoader = bevvyLoader;
		this.chunksInSegment = chunksInSegment;
		this.chunkSize = chunkSize;
		this.codec = codec;
		this.decryptor = decryptor;
		this.totalSize = totalSize;
	}

	@Override
	public ByteBuffer apply(Long offset) {
		// Determine the bevvy ID.
		long bevvyID = (offset / chunkSize) / chunksInSegment;
		BevvyIndex index = bevvyCache.get((int) bevvyID, bevvyLoader);
		if (index == null) {
			logger.error("Failed to read bevvy index");
			return null;
		}
		// Determine the offset into the bevvy index our chunk is.
		long chunkID = (offset / chunkSize) % chunksInSegment;
		ImageStreamPoint point = index.getPoint((int) chunkID);
		if (point == null) {
			logger.error("Failed to read bevvy index point");
			return null;
		}

		long chunkLength = point.getLength();
		SeekableByteChannel sbc = channel;
		long chunkOffset = index.getEntry().getDataOffset() + point.getOffset();
		ByteBuffer buffer = ByteBuffer.allocateDirect((int) chunkLength).order(ByteOrder.LITTLE_ENDIAN);

		if (index.getEntry().getMethod() != ZipMethod.STORED.getCode()) {
			try {
				IAFF4ImageStream stream = parent.getSegmentNoSanitize(index.getEntry().getName());
				sbc = stream.getChannel();
				chunkOffset = point.getOffset();
			}
			catch (IOException e) {
				logger.error(e.getMessage(), e);
				return null;
			}
		}

		try {
			int toRead = (int) chunkLength;
			// In all typical circumstances this should be a single read, but be careful otherwise.
			while (toRead > 0) {

				sbc.position(chunkOffset);
				int read = sbc.read(buffer);
				
				if (read <= 0) {
					break;
				}
				toRead -= read;
				chunkOffset += read;
			}
			buffer.flip();
			if (toRead > 0) {
				throw new IOException("Failed to read");
			}
			// now decompress if the buffer is not chunk length;
			if (chunkLength != chunkSize) {   
				try {
					buffer = codec.decompress(buffer);
				}catch(IOException ioe){
					// Fixing axiom not compressing entries and providing wrong compression info in turtle. so we skip error if block is equal total size. Just allowing decompression to
					// happen in case there is some compression info (miraculously) to get it removed .
					if(offset+chunkLength != totalSize){
						throw ioe;
					}
				}
			}
			if (decryptor != null) {
				buffer = decryptor.decrypt(buffer, bevvyID * chunksInSegment + chunkID);
			}

			return buffer;
		}
		catch (Throwable e) {
			logger.error(e.getMessage(), e);
		}
		return null;
	}

}
