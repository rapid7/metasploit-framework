/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.crypto");

//	enumerations for use in crypto code. Note that 0 == default, for the most part.
dojo.crypto.cipherModes={ ECB:0, CBC:1, PCBC:2, CFB:3, OFB:4, CTR:5 };
dojo.crypto.outputTypes={ Base64:0,Hex:1,String:2,Raw:3 };
