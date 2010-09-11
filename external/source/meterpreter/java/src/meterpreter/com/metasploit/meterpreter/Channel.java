package com.metasploit.meterpreter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A meterpreter channel. Channels are basically a collection of streams to interact with. Specialized subclasses of this class may handle special channels.
 * 
 * @author mihi
 */
public class Channel {

	private final InputStream in;
	private final OutputStream out;
	private final int id;
	protected final Meterpreter meterpreter;
	private boolean active = false, closed = false, waiting = false;
	private byte[] toRead;

	/**
	 * Create a new "generic" channel.
	 * 
	 * @param meterpreter
	 *            The meterpreter this channel should be assigned to.
	 * @param in
	 *            Input stream of the channel
	 * @param out
	 *            Output stream of the channel, if any
	 */
	public Channel(Meterpreter meterpreter, InputStream in, OutputStream out) {
		this.meterpreter = meterpreter;
		this.id = meterpreter.registerChannel(this);
		this.in = in;
		this.out = out;
		new InteractThread(in).start();
	}

	/**
	 * Close this channel and deregister it from the meterpreter.
	 */
	public synchronized void close() throws IOException {
		in.close();
		if (out != null)
			out.close();
		meterpreter.channelClosed(id);
		active = false;
		closed = true;
		notifyAll();
	}

	/**
	 * Check whether this channel is at end of file.
	 * 
	 * Note that even if this returns false, a subsequent read might return <code>null</code> for EOF, when the channel's state switches from "no data available" to EOF between the two calls.
	 */
	public synchronized boolean isEOF() throws IOException {
		if (active)
			throw new IllegalStateException("Cannot read; currently interacting with this channel");
		// when we are just waiting to read the EOF, close it
		if (waiting && toRead == null)
			close();
		return closed;
	}

	/**
	 * Read at least one byte, and up to maxLength bytes from this stream.
	 * 
	 * @param maxLength
	 *            The maximum number of bytes to read.
	 * @return The bytes read, or <code>null</code> if the end of the stream has been reached.
	 */
	public synchronized byte[] read(int maxLength) throws IOException, InterruptedException {
		if (closed)
			return null;
		if (active)
			throw new IllegalStateException("Cannot read; currently interacting with this channel");
		while (!waiting || (toRead != null && toRead.length == 0))
			wait();
		if (toRead == null)
			return null;
		byte[] result = new byte[Math.min(toRead.length, maxLength)];
		System.arraycopy(toRead, 0, result, 0, result.length);
		byte[] rest = new byte[toRead.length - result.length];
		System.arraycopy(toRead, result.length, rest, 0, rest.length);
		toRead = rest;
		notifyAll();
		return result;
	}

	/**
	 * Write length bytes from the start of data to this channel.
	 * 
	 * @param data
	 *            The data to write
	 * @param length
	 *            The length to write
	 */
	public void write(byte[] data, int length, TLVPacket request) throws IOException {
		if (out == null)
			throw new IOException("Channel does not have an output stream");
		out.write(data, 0, length);
		out.flush();
	}

	/**
	 * Get the ID of this channel.
	 */
	public int getID() {
		return id;
	}

	/**
	 * Start interacting with this channel.
	 */
	public synchronized void startInteract() {
		if (active)
			throw new IllegalStateException("Already interacting");
		active = true;
		notifyAll();
	}

	/**
	 * Stop interacting with this channel.
	 */
	public synchronized void stopInteract() {
		active = false;
	}

	/**
	 * Called from the {@link InteractThread} to notify the meterpreter of new data available on this channel.
	 * 
	 * @param data
	 *            The new data available, or <code>null</code> if EOF has been reached.
	 */
	protected synchronized void handleInteract(byte[] data) throws IOException, InterruptedException {
		while (waiting) {
			wait();
		}
		toRead = data;
		waiting = true;
		notifyAll();
		while (!active && !closed && (toRead == null || toRead.length > 0))
			wait();
		if ((toRead == null || toRead.length > 0) && !closed) {
			TLVPacket tlv = new TLVPacket();
			tlv.add(TLVType.TLV_TYPE_CHANNEL_ID, getID());
			String method;
			if (toRead == null) {
				method = "core_channel_close";
				close();
			} else {
				method = "core_channel_write";
				tlv.add(TLVType.TLV_TYPE_CHANNEL_DATA, toRead);
				tlv.add(TLVType.TLV_TYPE_LENGTH, toRead.length);
			}
			meterpreter.writeRequestPacket(method, tlv);
		}
		waiting = false;
		notifyAll();
	}

	/**
	 * A thread that polls the channel to provide information when interacting with this channel.
	 */
	protected class InteractThread extends Thread {
		private final InputStream stream;

		public InteractThread(InputStream stream) {
			this.stream = stream;
		}

		public void run() {
			try {
				byte[] buffer = new byte[4096];
				int len;
				while ((len = stream.read(buffer)) != -1) {
					if (len == 0)
						continue;
					byte[] data = new byte[len];
					System.arraycopy(buffer, 0, data, 0, len);
					handleInteract(data);
				}
				handleInteract(null);
			} catch (Throwable t) {
				t.printStackTrace(meterpreter.getErrorStream());
			}
		}
	}
}
