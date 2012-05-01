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

import com.rubyeventmachine.*;
import com.rubyeventmachine.application.*;
import java.io.*;

import org.junit.Assert;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


public class TestTimers {

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
	public final void test2() throws IOException {
		Application a = new Application();
		a.addTimer(0, new Timer() {
			public void fire() {
				application.stop();
			}
		});
		a.run();
		Assert.assertEquals (1, 1); // just to make sure the reactor halts.
	}
	
	@Test
	public final void test3() throws IOException {
		Application a = new Application();
		a.addTimer (0.1, new PeriodicTimer() {
			int n = 0;
			public void fire() {
				n++;
				if (n == 5)
					application.stop();
			}
		});
		a.run();
		Assert.assertEquals(1, 1);
	}
}
