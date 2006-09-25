/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.validate.us");
dojo.require("dojo.validate.common");

/**
  Validates U.S. currency.

  @param value  A string.
  @param flags  An object.
    flags in validate.isCurrency can be applied.
  @return  true or false.
*/
dojo.validate.us.isCurrency = function(value, flags) {
	return dojo.validate.isCurrency(value, flags);
}


/**
  Validates US state and territory abbreviations.

	@param value  A two character string.
  @param flags  An object.
    flags.allowTerritories  Allow Guam, Puerto Rico, etc.  Default is true.
    flags.allowMilitary  Allow military 'states', e.g. Armed Forces Europe (AE).  Default is true.
  @return  true or false
*/
dojo.validate.us.isState = function(value, flags) {
	var re = new RegExp("^" + dojo.regexp.us.state(flags) + "$", "i");
	return re.test(value);
}

/**
  Validates 10 US digit phone number for several common formats:

  @param value The telephone number string
  @return true or false
*/
dojo.validate.us.isPhoneNumber = function(value) {
	var flags = {
		format: [
			"###-###-####",
			"(###) ###-####",
			"(###) ### ####",
			"###.###.####",
			"###/###-####",
			"### ### ####",
			"###-###-#### x#???",
			"(###) ###-#### x#???",
			"(###) ### #### x#???",
			"###.###.#### x#???",
			"###/###-#### x#???",
			"### ### #### x#???",
			"##########"
		]
	};

	return dojo.validate.isNumberFormat(value, flags);
}

// Validates social security number
dojo.validate.us.isSocialSecurityNumber = function(value) {
	var flags = {
		format: [
			"###-##-####",
			"### ## ####",
			"#########"
		]
	};

	return dojo.validate.isNumberFormat(value, flags);
}

// Validates U.S. zip-code
dojo.validate.us.isZipCode = function(value) {
	var flags = {
		format: [
			"#####-####",
			"##### ####",
			"#########",
			"#####"
		]
	};

	return dojo.validate.isNumberFormat(value, flags);
}
