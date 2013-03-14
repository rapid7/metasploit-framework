/**
 * $Id$
 * 
 * Author:: Francis Cianfrocca (gmail: blackhedd)
 * Homepage::  http://rubyeventmachine.com
 * Date:: 15 Jul 2007
 * 
 * See EventMachine and EventMachine::Connection for documentation and
 * usage examples.
 * 
 *
 *----------------------------------------------------------------------------
 *
 * Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
 * Gmail: blackhedd
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of either: 1) the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version; or 2) Ruby's License.
 * 
 * See the file COPYING for complete licensing information.
 *
 *---------------------------------------------------------------------------
 *
 * 
 */

/**
 * 
 */
package com.rubyeventmachine;

/**
 * @author francis
 *
 */

import java.nio.channels.*;
import java.nio.*;
import java.util.*;
import java.io.*;
import java.net.Socket;
import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.*;
import java.lang.reflect.Field;

import java.security.*;

public class EventableSocketChannel implements EventableChannel {
	Selector selector;
	SelectionKey channelKey;
	SocketChannel channel;

	long binding;
	LinkedList<ByteBuffer> outboundQ;

	boolean bCloseScheduled;
	boolean bConnectPending;
	boolean bWatchOnly;
	boolean bAttached;
	boolean bNotifyReadable;
	boolean bNotifyWritable;
	
	SSLEngine sslEngine;
	SSLContext sslContext;

	public EventableSocketChannel (SocketChannel sc, long _binding, Selector sel) {
		channel = sc;
		binding = _binding;
		selector = sel;
		bCloseScheduled = false;
		bConnectPending = false;
		bWatchOnly = false;
		bAttached = false;
		bNotifyReadable = false;
		bNotifyWritable = false;
		outboundQ = new LinkedList<ByteBuffer>();
	}
	
	public long getBinding() {
		return binding;
	}

	public SocketChannel getChannel() {
		return channel;
	}

	public void register() throws ClosedChannelException {
		if (channelKey == null) {
			int events = currentEvents();
			channelKey = channel.register(selector, events, this);
		}
	}

	/**
	 * Terminate with extreme prejudice. Don't assume there will be another pass through
	 * the reactor core.
	 */
	public void close() {
		if (channelKey != null) {
			channelKey.cancel();
			channelKey = null;
		}

		if (bAttached) {
			// attached channels are copies, so reset the file descriptor to prevent java from close()ing it
			Field f;
			FileDescriptor fd;

			try {
				/* do _NOT_ clobber fdVal here, it will break epoll/kqueue on jdk6!
				 * channelKey.cancel() above does not occur until the next call to select
				 * and if fdVal is gone, we will continue to get events for this fd.
				 *
				 * instead, remove fdVal in cleanup(), which is processed via DetachedConnections,
				 * after UnboundConnections but before NewConnections.
				 */

				f = channel.getClass().getDeclaredField("fd");
				f.setAccessible(true);
				fd = (FileDescriptor) f.get(channel);

				f = fd.getClass().getDeclaredField("fd");
				f.setAccessible(true);
				f.set(fd, -1);
			} catch (java.lang.NoSuchFieldException e) {
				e.printStackTrace();
			} catch (java.lang.IllegalAccessException e) {
				e.printStackTrace();
			}

			return;
		}

		try {
			channel.close();
		} catch (IOException e) {
		}
	}

	public void cleanup() {
		if (bAttached) {
			Field f;
			try {
				f = channel.getClass().getDeclaredField("fdVal");
				f.setAccessible(true);
				f.set(channel, -1);
			} catch (java.lang.NoSuchFieldException e) {
				e.printStackTrace();
			} catch (java.lang.IllegalAccessException e) {
				e.printStackTrace();
			}
		}

		channel = null;
	}
	
	public void scheduleOutboundData (ByteBuffer bb) {
		if (!bCloseScheduled && bb.remaining() > 0) {
			if (sslEngine != null) {
				try {
					ByteBuffer b = ByteBuffer.allocate(32*1024); // TODO, preallocate this buffer.
					sslEngine.wrap(bb, b);
					b.flip();
					outboundQ.addLast(b);
				} catch (SSLException e) {
					throw new RuntimeException ("ssl error");
				}
			}
			else {
				outboundQ.addLast(bb);
			}

			updateEvents();
		}
	}
	
	public void scheduleOutboundDatagram (ByteBuffer bb, String recipAddress, int recipPort) {
		throw new RuntimeException ("datagram sends not supported on this channel");
	}
	
	/**
	 * Called by the reactor when we have selected readable.
	 */
	public void readInboundData (ByteBuffer bb) throws IOException {
		if (channel.read(bb) == -1)
			throw new IOException ("eof");
	}

	/**
	 * Called by the reactor when we have selected writable.
	 * Return false to indicate an error that should cause the connection to close.
	 * TODO, VERY IMPORTANT: we're here because we selected writable, but it's always
	 * possible to become unwritable between the poll and when we get here. The way
	 * this code is written, we're depending on a nonblocking write NOT TO CONSUME
	 * the whole outbound buffer in this case, rather than firing an exception.
	 * We should somehow verify that this is indeed Java's defined behavior.
	 * Also TODO, see if we can use gather I/O rather than one write at a time.
	 * Ought to be a big performance enhancer.
	 * @return
	 */
	public boolean writeOutboundData() throws IOException {
		while (!outboundQ.isEmpty()) {
			ByteBuffer b = outboundQ.getFirst();
			if (b.remaining() > 0)
				channel.write(b);

			// Did we consume the whole outbound buffer? If yes,
			// pop it off and keep looping. If no, the outbound network
			// buffers are full, so break out of here.
			if (b.remaining() == 0)
				outboundQ.removeFirst();
			else
				break;
		}

		if (outboundQ.isEmpty() && !bCloseScheduled) {
			updateEvents();
		}

		// ALWAYS drain the outbound queue before triggering a connection close.
		// If anyone wants to close immediately, they're responsible for clearing
		// the outbound queue.
		return (bCloseScheduled && outboundQ.isEmpty()) ? false : true;
 	}
	
	public void setConnectPending() {
		bConnectPending = true;
		updateEvents();
	}
	
	/**
	 * Called by the reactor when we have selected connectable.
	 * Return false to indicate an error that should cause the connection to close.
	 */
	public boolean finishConnecting() throws IOException {
		channel.finishConnect();

		bConnectPending = false;
		updateEvents();
		return true;
	}
	
	public boolean scheduleClose (boolean afterWriting) {
		// TODO: What the hell happens here if bConnectPending is set?
		if (!afterWriting)
			outboundQ.clear();

		if (outboundQ.isEmpty())
			return true;
		else {
			updateEvents();
			bCloseScheduled = true;
			return false;
		}
	}

	public void startTls() {
		if (sslEngine == null) {
			try {
				sslContext = SSLContext.getInstance("TLS");
				sslContext.init(null, null, null); // TODO, fill in the parameters.
				sslEngine = sslContext.createSSLEngine(); // TODO, should use the parameterized version, to get Kerb stuff and session re-use.
				sslEngine.setUseClientMode(false);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException ("unable to start TLS"); // TODO, get rid of this.				
			} catch (KeyManagementException e) {
				throw new RuntimeException ("unable to start TLS"); // TODO, get rid of this.				
			}
		}
		System.out.println ("Starting TLS");
	}
	
	public ByteBuffer dispatchInboundData (ByteBuffer bb) throws SSLException {
		if (sslEngine != null) {
			if (true) throw new RuntimeException ("TLS currently unimplemented");
			System.setProperty("javax.net.debug", "all");
			ByteBuffer w = ByteBuffer.allocate(32*1024); // TODO, WRONG, preallocate this buffer.
			SSLEngineResult res = sslEngine.unwrap(bb, w);
			if (res.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
				Runnable r;
				while ((r = sslEngine.getDelegatedTask()) != null) {
					r.run();
				}
			}
			System.out.println (bb);
			w.flip();
			return w;
		}
		else
			return bb;
	}

	public void setCommInactivityTimeout (long seconds) {
		// TODO
		System.out.println ("SOCKET: SET COMM INACTIVITY UNIMPLEMENTED " + seconds);
	}

	public Object[] getPeerName () {
		Socket sock = channel.socket();
		return new Object[]{ sock.getPort(), sock.getInetAddress().getHostAddress() };
	}

	public void setWatchOnly() {
		bWatchOnly = true;
		updateEvents();
	}
	public boolean isWatchOnly() { return bWatchOnly; }

	public void setAttached() {
		bAttached = true;
	}
	public boolean isAttached() { return bAttached; }

	public void setNotifyReadable (boolean mode) {
		bNotifyReadable = mode;
		updateEvents();
	}
	public boolean isNotifyReadable() { return bNotifyReadable; }

	public void setNotifyWritable (boolean mode) {
		bNotifyWritable = mode;
		updateEvents();
	}
	public boolean isNotifyWritable() { return bNotifyWritable; }

	private void updateEvents() {
		if (channelKey == null)
			return;

		int events = currentEvents();

		if (channelKey.interestOps() != events) {
			channelKey.interestOps(events);
		}
	}

	private int currentEvents() {
		int events = 0;

		if (bWatchOnly)
		{
			if (bNotifyReadable)
				events |= SelectionKey.OP_READ;

			if (bNotifyWritable)
				events |= SelectionKey.OP_WRITE;
		}
		else
		{
			if (bConnectPending)
				events |= SelectionKey.OP_CONNECT;
			else {
				events |= SelectionKey.OP_READ;

				if (!outboundQ.isEmpty())
					events |= SelectionKey.OP_WRITE;
			}
		}

		return events;
	}
}
