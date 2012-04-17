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

public class Timer {
	/**
	 * User code is expected to call a method on a controlling Application,
	 * which will fill in this field so subsequent user code can access it.
	 */
	public Application application;
	public double interval;
	
	/**
	 * The reactor calls here, and it may be overridden in subclasses.
	 * User code should never call this method.
	 */
	public void _fire() {
		fire();
	}

	/**
	 * User code is expected to override this method.
	 */
	public void fire() {
	}

}
