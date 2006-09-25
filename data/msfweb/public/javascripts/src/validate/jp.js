/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.validate.jp");
dojo.require("dojo.validate.common");

/**
  Validates Japanese currency.

  @param value  A string.
  @return  true or false.
*/
dojo.validate.isJapaneseCurrency = function(value) {
	var flags = {
		symbol: "�",
		cents: false
	};
	return dojo.validate.isCurrency(value, flags);
}


