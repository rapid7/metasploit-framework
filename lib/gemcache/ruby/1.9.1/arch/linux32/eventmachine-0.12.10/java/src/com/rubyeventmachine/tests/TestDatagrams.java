package com.rubyeventmachine.tests;

import com.rubyeventmachine.application.*;
import java.net.*;
import java.nio.*;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


public class TestDatagrams {

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

	class A extends Connection {
		public void receiveData (ByteBuffer bb) {
			application.stop();
		}
	}
	class B extends Connection {
		public void postInit() {
			this.sendDatagram(ByteBuffer.wrap(new String("ABC").getBytes()), new InetSocketAddress ("127.0.0.1", 9550));
		}
		
	}
	@Test
	public final void testA() {
		final Application a = new Application();
		a.run (new Runnable() {
			public void run() {
				a.openDatagramSocket( new InetSocketAddress ("0.0.0.0", 9550), new A() );
				a.openDatagramSocket( new B() );
			}
		});
	}
}
