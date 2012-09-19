/**
 * $Id$
 * 
 * Author:: Francis Cianfrocca (gmail: blackhedd)
 * Homepage:: http://rubyeventmachine.com
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

package com.rubyeventmachine;

import java.io.*;
import java.nio.channels.*;
import java.util.*;
import java.nio.*;
import java.net.*;
import java.util.concurrent.atomic.*;
import java.security.*;

public class EmReactor {
	public final int EM_TIMER_FIRED = 100;
	public final int EM_CONNECTION_READ = 101;
	public final int EM_CONNECTION_UNBOUND = 102;
	public final int EM_CONNECTION_ACCEPTED = 103;
	public final int EM_CONNECTION_COMPLETED = 104;
	public final int EM_LOOPBREAK_SIGNAL = 105;
	public final int EM_CONNECTION_NOTIFY_READABLE = 106;
	public final int EM_CONNECTION_NOTIFY_WRITABLE = 107;
	public final int EM_SSL_HANDSHAKE_COMPLETED = 108;
	public final int EM_SSL_VERIFY = 109;
	public final int EM_PROXY_TARGET_UNBOUND = 110;

	private Selector mySelector;
	private TreeMap<Long, ArrayList<Long>> Timers;
	private HashMap<Long, EventableChannel> Connections;
	private HashMap<Long, ServerSocketChannel> Acceptors;
	private ArrayList<Long> NewConnections;
	private ArrayList<Long> UnboundConnections;
	private ArrayList<EventableSocketChannel> DetachedConnections;

	private boolean bRunReactor;
	private long BindingIndex;
	private AtomicBoolean loopBreaker;
	private ByteBuffer myReadBuffer;
	private int timerQuantum;

	public EmReactor() {
		Timers = new TreeMap<Long, ArrayList<Long>>();
		Connections = new HashMap<Long, EventableChannel>();
		Acceptors = new HashMap<Long, ServerSocketChannel>();
		NewConnections = new ArrayList<Long>();
		UnboundConnections = new ArrayList<Long>();
		DetachedConnections = new ArrayList<EventableSocketChannel>();

		BindingIndex = 0;
		loopBreaker = new AtomicBoolean();
		loopBreaker.set(false);
		myReadBuffer = ByteBuffer.allocate(32*1024); // don't use a direct buffer. Ruby doesn't seem to like them.
		timerQuantum = 98;
	}

	/**
	 * This is a no-op stub, intended to be overridden in user code.
	 */
	public void eventCallback (long sig, int eventType, ByteBuffer data, long data2) {
		System.out.println ("Default callback: "+sig+" "+eventType+" "+data+" "+data2);
	}
	public void eventCallback (long sig, int eventType, ByteBuffer data) {
		eventCallback (sig, eventType, data, 0);
	}


	public void run() {
		try {
			mySelector = Selector.open();
			bRunReactor = true;
		} catch (IOException e) {
			throw new RuntimeException ("Could not open selector", e);
		}

		while (bRunReactor) {
			runLoopbreaks();
			if (!bRunReactor) break;

			runTimers();
			if (!bRunReactor) break;

			removeUnboundConnections();
			checkIO();
			addNewConnections();
			processIO();
		}

		close();
	}

	void addNewConnections() {
		ListIterator<EventableSocketChannel> iter = DetachedConnections.listIterator(0);
		while (iter.hasNext()) {
			EventableSocketChannel ec = iter.next();
			ec.cleanup();
		}
		DetachedConnections.clear();

		ListIterator<Long> iter2 = NewConnections.listIterator(0);
		while (iter2.hasNext()) {
			long b = iter2.next();

			EventableChannel ec = Connections.get(b);
			if (ec != null) {
				try {
					ec.register();
				} catch (ClosedChannelException e) {
					UnboundConnections.add (ec.getBinding());
				}
			}
		}
		NewConnections.clear();
	}

	void removeUnboundConnections() {
		ListIterator<Long> iter = UnboundConnections.listIterator(0);
		while (iter.hasNext()) {
			long b = iter.next();

			EventableChannel ec = Connections.remove(b);
			if (ec != null) {
				eventCallback (b, EM_CONNECTION_UNBOUND, null);
				ec.close();

				EventableSocketChannel sc = (EventableSocketChannel) ec;
				if (sc != null && sc.isAttached())
					DetachedConnections.add (sc);
			}
		}
		UnboundConnections.clear();
	}

	void checkIO() {
		long timeout;

		if (NewConnections.size() > 0) {
			timeout = -1;
		} else if (!Timers.isEmpty()) {
			long now = new Date().getTime();
			long k = Timers.firstKey();
			long diff = k-now;

			if (diff <= 0)
				timeout = -1; // don't wait, just poll once
			else
				timeout = diff;
		} else {
			timeout = 0; // wait indefinitely
		}

		try {
			if (timeout == -1)
				mySelector.selectNow();
			else
				mySelector.select(timeout);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	void processIO() {
		Iterator<SelectionKey> it = mySelector.selectedKeys().iterator();
		while (it.hasNext()) {
			SelectionKey k = it.next();
			it.remove();

			if (k.isConnectable())
				isConnectable(k);

			else if (k.isAcceptable())
				isAcceptable(k);

			else {
				if (k.isWritable())
					isWritable(k);

				if (k.isReadable())
					isReadable(k);
			}
		}
	}

	void isAcceptable (SelectionKey k) {
		ServerSocketChannel ss = (ServerSocketChannel) k.channel();
		SocketChannel sn;
		long b;

		for (int n = 0; n < 10; n++) {
			try {
				sn = ss.accept();
				if (sn == null)
					break;
			} catch (IOException e) {
				e.printStackTrace();
				k.cancel();

				ServerSocketChannel server = Acceptors.remove(k.attachment());
				if (server != null)
					try{ server.close(); } catch (IOException ex) {};
				break;
			}

			try {
				sn.configureBlocking(false);
			} catch (IOException e) {
				e.printStackTrace();
				continue;
			}

			b = createBinding();
			EventableSocketChannel ec = new EventableSocketChannel (sn, b, mySelector);
			Connections.put (b, ec);
			NewConnections.add (b);

			eventCallback (((Long)k.attachment()).longValue(), EM_CONNECTION_ACCEPTED, null, b);
		}
	}

	void isReadable (SelectionKey k) {
		EventableChannel ec = (EventableChannel) k.attachment();
		long b = ec.getBinding();

		if (ec.isWatchOnly()) {
			if (ec.isNotifyReadable())
				eventCallback (b, EM_CONNECTION_NOTIFY_READABLE, null);
		} else {
			myReadBuffer.clear();

			try {
				ec.readInboundData (myReadBuffer);
				myReadBuffer.flip();
				if (myReadBuffer.limit() > 0)
					eventCallback (b, EM_CONNECTION_READ, myReadBuffer);
			} catch (IOException e) {
				UnboundConnections.add (b);
			}
		}
	}

	void isWritable (SelectionKey k) {
		EventableChannel ec = (EventableChannel) k.attachment();
		long b = ec.getBinding();

		if (ec.isWatchOnly()) {
			if (ec.isNotifyWritable())
				eventCallback (b, EM_CONNECTION_NOTIFY_WRITABLE, null);
		}
		else {
			try {
				if (!ec.writeOutboundData())
					UnboundConnections.add (b);
			} catch (IOException e) {
				UnboundConnections.add (b);
			}
		}
	}

	void isConnectable (SelectionKey k) {
		EventableSocketChannel ec = (EventableSocketChannel) k.attachment();
		long b = ec.getBinding();

		try {
			if (ec.finishConnecting())
				eventCallback (b, EM_CONNECTION_COMPLETED, null);
			else
				UnboundConnections.add (b);
		} catch (IOException e) {
			UnboundConnections.add (b);
		}
	}

	void close() {
		try {
			if (mySelector != null)
				mySelector.close();
		} catch (IOException e) {}
		mySelector = null;

		// run down open connections and sockets.
		Iterator<ServerSocketChannel> i = Acceptors.values().iterator();
		while (i.hasNext()) {
			try {
				i.next().close();
			} catch (IOException e) {}
		}

		// 29Sep09: We create an ArrayList of the existing connections, then iterate over
		// that to call unbind on them. This is because an unbind can trigger a reconnect,
		// which will add to the Connections HashMap, causing a ConcurrentModificationException.
		// XXX: The correct behavior here would be to latch the various reactor methods to return
		// immediately if the reactor is shutting down.
		ArrayList<EventableChannel> conns = new ArrayList<EventableChannel>();
		Iterator<EventableChannel> i2 = Connections.values().iterator();
		while (i2.hasNext()) {
			EventableChannel ec = i2.next();
			if (ec != null) {
				conns.add (ec);
			}
		}
		Connections.clear();

		ListIterator<EventableChannel> i3 = conns.listIterator(0);
		while (i3.hasNext()) {
			EventableChannel ec = i3.next();
			eventCallback (ec.getBinding(), EM_CONNECTION_UNBOUND, null);
			ec.close();

			EventableSocketChannel sc = (EventableSocketChannel) ec;
			if (sc != null && sc.isAttached())
				DetachedConnections.add (sc);
		}

		ListIterator<EventableSocketChannel> i4 = DetachedConnections.listIterator(0);
		while (i4.hasNext()) {
			EventableSocketChannel ec = i4.next();
			ec.cleanup();
		}
		DetachedConnections.clear();
	}

	void runLoopbreaks() {
		if (loopBreaker.getAndSet(false)) {
			eventCallback (0, EM_LOOPBREAK_SIGNAL, null);
		}
	}

	public void stop() {
		bRunReactor = false;
		signalLoopbreak();
	}

	void runTimers() {
		long now = new Date().getTime();
		while (!Timers.isEmpty()) {
			long k = Timers.firstKey();
			if (k > now)
				break;

			ArrayList<Long> callbacks = Timers.get(k);
			Timers.remove(k);

			// Fire all timers at this timestamp
			ListIterator<Long> iter = callbacks.listIterator(0);
			while (iter.hasNext()) {
				eventCallback (0, EM_TIMER_FIRED, null, iter.next().longValue());
			}
		}
	}

	public long installOneshotTimer (int milliseconds) {
		long s = createBinding();
		long deadline = new Date().getTime() + milliseconds;

		if (Timers.containsKey(deadline)) {
			Timers.get(deadline).add(s);
		} else {
			ArrayList<Long> callbacks = new ArrayList<Long>();
			callbacks.add(s);
			Timers.put(deadline, callbacks);
		}

		return s;
	}

	public long startTcpServer (SocketAddress sa) throws EmReactorException {
		try {
			ServerSocketChannel server = ServerSocketChannel.open();
			server.configureBlocking(false);
			server.socket().bind (sa);
			long s = createBinding();
			Acceptors.put(s, server);
			server.register(mySelector, SelectionKey.OP_ACCEPT, s);
			return s;
		} catch (IOException e) {
			throw new EmReactorException ("unable to open socket acceptor: " + e.toString());
		}
	}

	public long startTcpServer (String address, int port) throws EmReactorException {
		return startTcpServer (new InetSocketAddress (address, port));
	}

	public void stopTcpServer (long signature) throws IOException {
		ServerSocketChannel server = Acceptors.remove(signature);
		if (server != null)
			server.close();
		else
			throw new RuntimeException ("failed to close unknown acceptor");
	}

	public long openUdpSocket (InetSocketAddress address) throws IOException {
		// TODO, don't throw an exception out of here.
		DatagramChannel dg = DatagramChannel.open();
		dg.configureBlocking(false);
		dg.socket().bind(address);
		long b = createBinding();
		EventableChannel ec = new EventableDatagramChannel (dg, b, mySelector);
		dg.register(mySelector, SelectionKey.OP_READ, ec);
		Connections.put(b, ec);
		return b;
	}

	public long openUdpSocket (String address, int port) throws IOException {
		return openUdpSocket (new InetSocketAddress (address, port));
	}

	public void sendData (long sig, ByteBuffer bb) throws IOException {
		Connections.get(sig).scheduleOutboundData( bb );
	}

	public void sendData (long sig, byte[] data) throws IOException {
		sendData (sig, ByteBuffer.wrap(data));
	}

	public void setCommInactivityTimeout (long sig, long mills) {
		Connections.get(sig).setCommInactivityTimeout (mills);
	}

	public void sendDatagram (long sig, String data, int length, String recipAddress, int recipPort) {
		sendDatagram (sig, ByteBuffer.wrap(data.getBytes()), recipAddress, recipPort);
	}

	public void sendDatagram (long sig, ByteBuffer bb, String recipAddress, int recipPort) {
		(Connections.get(sig)).scheduleOutboundDatagram( bb, recipAddress, recipPort);
	}

	public long connectTcpServer (String address, int port) {
		return connectTcpServer(null, 0, address, port);
	}

	public long connectTcpServer (String bindAddr, int bindPort, String address, int port) {
		long b = createBinding();

		try {
			SocketChannel sc = SocketChannel.open();
			sc.configureBlocking(false);
			if (bindAddr != null)
				sc.socket().bind(new InetSocketAddress (bindAddr, bindPort));

			EventableSocketChannel ec = new EventableSocketChannel (sc, b, mySelector);

			if (sc.connect (new InetSocketAddress (address, port))) {
				// Connection returned immediately. Can happen with localhost connections.
				// WARNING, this code is untested due to lack of available test conditions.
				// Ought to be be able to come here from a localhost connection, but that
				// doesn't happen on Linux. (Maybe on FreeBSD?)
				// The reason for not handling this until we can test it is that we
				// really need to return from this function WITHOUT triggering any EM events.
				// That's because until the user code has seen the signature we generated here,
				// it won't be able to properly dispatch them. The C++ EM deals with this
				// by setting pending mode as a flag in ALL eventable descriptors and making
				// the descriptor select for writable. Then, it can send UNBOUND and
				// CONNECTION_COMPLETED on the next pass through the loop, because writable will
				// fire.
				throw new RuntimeException ("immediate-connect unimplemented");
			}
			else {
				ec.setConnectPending();
				Connections.put (b, ec);
				NewConnections.add (b);
			}
		} catch (IOException e) {
			// Can theoretically come here if a connect failure can be determined immediately.
			// I don't know how to make that happen for testing purposes.
			throw new RuntimeException ("immediate-connect unimplemented: " + e.toString());
		}
		return b;
	}

	public void closeConnection (long sig, boolean afterWriting) {
		EventableChannel ec = Connections.get(sig);
		if (ec != null)
			if (ec.scheduleClose (afterWriting))
				UnboundConnections.add (sig);
	}
	
	long createBinding() {
		return ++BindingIndex;
	}

	public void signalLoopbreak() {
		loopBreaker.set(true);
		if (mySelector != null)
			mySelector.wakeup();
	}

	public void startTls (long sig) throws NoSuchAlgorithmException, KeyManagementException {
		Connections.get(sig).startTls();
	}

	public void setTimerQuantum (int mills) {
		if (mills < 5 || mills > 2500)
			throw new RuntimeException ("attempt to set invalid timer-quantum value: "+mills);
		timerQuantum = mills;
	}

	public Object[] getPeerName (long sig) {
		return Connections.get(sig).getPeerName();
	}

	public long attachChannel (SocketChannel sc, boolean watch_mode) {
		long b = createBinding();

		EventableSocketChannel ec = new EventableSocketChannel (sc, b, mySelector);

		ec.setAttached();
		if (watch_mode)
			ec.setWatchOnly();

		Connections.put (b, ec);
		NewConnections.add (b);

		return b;
	}

	public SocketChannel detachChannel (long sig) {
		EventableSocketChannel ec = (EventableSocketChannel) Connections.get (sig);
		if (ec != null) {
			UnboundConnections.add (sig);
			return ec.getChannel();
		} else {
			return null;
		}
	}

	public void setNotifyReadable (long sig, boolean mode) {
		((EventableSocketChannel) Connections.get(sig)).setNotifyReadable(mode);
	}

	public void setNotifyWritable (long sig, boolean mode) {
		((EventableSocketChannel) Connections.get(sig)).setNotifyWritable(mode);
	}

	public boolean isNotifyReadable (long sig) {
		return Connections.get(sig).isNotifyReadable();
	}

	public boolean isNotifyWritable (long sig) {
		return Connections.get(sig).isNotifyWritable();
	}

	public int getConnectionCount() {
	  return Connections.size() + Acceptors.size();
	}
}
