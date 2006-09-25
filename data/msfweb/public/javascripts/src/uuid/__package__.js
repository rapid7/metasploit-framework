/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.kwCompoundRequire({
	common: [
		"dojo.uuid.Uuid",
		"dojo.uuid.LightweightGenerator",
		"dojo.uuid.RandomGenerator",
		"dojo.uuid.TimeBasedGenerator",
		"dojo.uuid.NameBasedGenerator",
		"dojo.uuid.NilGenerator"
	]
});
dojo.provide("dojo.uuid.*");

