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
import java.net.*;
import java.io.*;
import java.nio.*;
import java.nio.channels.*;

import com.rubyeventmachine.*;
import com.rubyeventmachine.application.*;

public class ConnectTest {

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
	public final void test1() throws IOException, ClosedChannelException {
		Application a = new Application();
		a.addTimer(0, new Timer() {
			public void fire() {
				application.connect("www.bayshorenetworks.com", 80, new Connection() {
					public void connectionCompleted() {
						close();
					}
					public void unbind() {
						application.stop();
					}
				});
			}
		});
		a.run();
	}
	
	@Test
	public final void test2() throws IOException {
		class Bays extends Connection {
			public void connectionCompleted() {
				sendData (ByteBuffer.wrap( new String ("GET / HTTP/1.1\r\nHost: _\r\n\r\n").getBytes()));
			}
			public void receiveData (ByteBuffer b) {
				System.out.println (new String(b.array()));
				application.stop();
			}
		};
		
		Application a = new Application();
		a.addTimer(0, new Timer() {
			public void fire() {
				application.connect("www.bayshorenetworks.com", 80, new Bays());
			}
		});
		a.run();
	}

	public final void testBindConnect() throws IOException {
		class Server extends Connection {
			public void postInit() {
				// TODO: get peername here and check if the port is 33333
				// doesnt seem like peername is impl yet?
				System.out.println("post init!");
			}
		};

		Application a = new Application();
		a.addTimer(0, new Timer() {
			public void fire() {
				application.startServer(new InetSocketAddress("localhost", 20000), new DefaultConnectionFactory());
			}
		});
		a.addTimer(500, new Timer() {
			public void fire() {
				application.bindConnect("localhost", 33333, "localhost", 20000, new Connection());
			}
		});

		a.run();
	}

	class C1 extends Connection {
		Application application;
		public C1 (Application a) {
			application = a;
		}
		public void postInit() {
			application.stop();
		}
	}
	@Test
	public final void test3() {
		final Application a = new Application();
		a.run (new Runnable() {
			public void run() {
				a.connect("www.bayshorenetworks.com", 80, new C1(a));
			}
		});
	}
	
	

}
