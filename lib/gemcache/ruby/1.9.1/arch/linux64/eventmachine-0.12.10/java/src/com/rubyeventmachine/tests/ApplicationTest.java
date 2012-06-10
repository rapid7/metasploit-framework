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



package com.rubyeventmachine.tests;


import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Assert;
import java.net.*;
import java.io.*;
import java.nio.*;

import com.rubyeventmachine.*;
import com.rubyeventmachine.application.*;

public class ApplicationTest {

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testRunnableArgument() {
		final Application a = new Application();
		a.run (new Runnable() {
			public void run() {
				a.stop();
			}
		});
	}
	

	
	class F implements ConnectionFactory {
		public Connection connection() {
			return new Connection() {
				public void receiveData (ByteBuffer bb) {
					application.stop();
				}
			};
		}
		
	};
	
	@Test
	public void testTcpServer() throws EmReactorException {
		final Application a = new Application();
		final SocketAddress saddr = new InetSocketAddress ("127.0.0.1", 9008);
		a.run (new Runnable() {
			public void run() {
				try {
					a.startServer (saddr, new F());
				} catch (EmReactorException e) { Assert.fail(); }
				new Thread() {
					public void run() {
						try {
							Socket s = new Socket ("127.0.0.1", 9008);
							s.getOutputStream().write(new String ("boo").getBytes());
						} catch (UnknownHostException e) {
						} catch (IOException e) {}
					}
				}.start();
			}
		});
	}
}
