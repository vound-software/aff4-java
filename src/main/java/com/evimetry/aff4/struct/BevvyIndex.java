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
import com.evimetry.aff4.container.AFF4ZipContainer;
import com.evimetry.aff4.imagestream.Streams;
import com.evimetry.aff4.rdf.NameCodec;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;

/**
 * An ImageStream/Bevvy index reader.
 */
public class BevvyIndex {

	private final ZipFile zipcontainer;
	/**
	 * The bevvy index ID which we represent
	 */
	private final int bevvyID;

	/**
	 * The offset of the first chunk in the parent's channel
	 */
	private final ZipArchiveEntry archiveEntry;

	/**
	 * The collection of image stream points.
	 */
	private ImageStreamPoint[] entries;

	/**
	 * Create a new Bevvy Index reader BxB ther are some inconsistencies in naming for different versions someties anaming differs so we will try to
	 * acquire zip segment by using different sanitization
	 *
	 * @param resource     The resource of the image stream we are servicing.
	 * @param bevvyID      The bevvy id
	 * @param parent       The parent zip container
	 * @param zipContainer The zip container.
	 * @throws IOException If reading the zip container fails.
	 */
	
	// TODO -- this is not right -- recheck 
	public BevvyIndex(String resource, int bevvyID, AFF4ZipContainer parent, ZipFile zipContainer)
			  throws IOException
	{
		String sanitized = resource;
		this.zipcontainer = zipContainer;

		this.bevvyID = bevvyID;

		// Get the offset of the bevvy segment into the primary channel.
		String bevvyChunkName = NameCodec.encode(String.format("%s/%08d", sanitized, bevvyID));
		ZipArchiveEntry entry = zipContainer.getEntry(bevvyChunkName);

		if (entry == null) {
			//if("1.1".equals(parent.getContainerVersion())) {
			//BxB -- for logical images
			sanitized = parent.sanitizeResource(resource);
			bevvyChunkName = NameCodec.encode(String.format("%s/%08d", sanitized, bevvyID));
			entry = zipContainer.getEntry(bevvyChunkName);
		}
		//else if("1.2".equals(parent.getContainerVersion())){
		if (entry == null) {
			bevvyChunkName = String.format("%s/%08d", resource, bevvyID);
			entry = zipContainer.getEntry(bevvyChunkName);
		}
		//}
		if (entry == null) {
			throw new IOException("Missing bevvy segment ["+bevvyChunkName+"]");
		}

		this.archiveEntry = entry;

		// Load the indices
		String bevvyIndexName = NameCodec.encode(String.format("%s/%08d.index", sanitized, bevvyID));
		IAFF4ImageStream stream = parent.getSegment(bevvyIndexName);

		if (stream == null && "1.2".equals(parent.getContainerVersion())) {
			bevvyIndexName = String.format("%s/%08d.index", resource, bevvyID);
			stream = parent.getSegmentNoSanitize(bevvyIndexName);
		}


		try (SeekableByteChannel channel = stream.getChannel()) {
			ByteBuffer buffer = ByteBuffer.allocateDirect((int) channel.size()).order(ByteOrder.LITTLE_ENDIAN);
			Streams.readFull(channel, 0, buffer);
			buffer.flip();
			int sz = ImageStreamPoint.getSize();
			this.entries = new ImageStreamPoint[buffer.remaining() / sz];
			int index = 0;
			while (buffer.remaining() >= sz) {
				entries[index++] = ImageStreamPoint.create(buffer);
			}
		}
	}

	/**
	 * Get the bevvy id.
	 *
	 * @return The Bevvy ID
	 */
	public int getBevvyID() {
		return bevvyID;
	}

	/**
	 * The offset of the first chunk in the parent's channel
	 *
	 * @return
	 */
	public ZipArchiveEntry getEntry() {
		return archiveEntry;
	}

	/**
	 * Get the image point for this region
	 *
	 * @param offset The chunk offset.
	 * @return The image point, or null if none exist.
	 */
	public ImageStreamPoint getPoint(int offset) {
		if (offset < 0 || offset >= entries.length) {
			return null;
		}
		return entries[offset];
	}


}
