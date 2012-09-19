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



package com.rubyeventmachine.application;

//import java.io.*;
import java.nio.*;
import java.net.*;
//import java.nio.channels.*;

public class Connection {
	
	public Application application;
	public long signature;
	
	public void postInit() {}
	public void connectionCompleted() {}
	public void unbind() {}
	public void receiveData (ByteBuffer bytebuffer) {}
	
	
	/**
	 * Called by user code.
	 * @param bytebuffer
	 */
	public void sendData (ByteBuffer b) {
		application.sendData(signature, b);
	}
	
	/**
	 * This is called by user code.
	 * TODO: don't expose the exception here.
	 */
	public void close() {
		application.closeConnection(signature, false);
	}
	/**
	 * This is called by user code/
	 */
	public void closeAfterWriting() {
		application.closeConnection(signature, true);
	}
	
	public void sendDatagram (ByteBuffer bb, InetSocketAddress addr) {
		application.sendDatagram (signature, bb, addr);
	}
}
