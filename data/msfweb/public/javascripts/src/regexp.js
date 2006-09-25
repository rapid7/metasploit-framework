/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.regexp");
dojo.provide("dojo.regexp.us");

// *** Regular Expression Generators ***

/**
  Builds a RE that matches a top-level domain.

  @param flags  An object.
    flags.allowCC  Include 2 letter country code domains.  Default is true.
    flags.allowGeneric  Include the generic domains.  Default is true.
    flags.allowInfra  Include infrastructure domains.  Default is true.

  @return  A string for a regular expression for a top-level domain.
*/
dojo.regexp.tld = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.allowCC != "boolean") { flags.allowCC = true; }
	if (typeof flags.allowInfra != "boolean") { flags.allowInfra = true; }
	if (typeof flags.allowGeneric != "boolean") { flags.allowGeneric = true; }

	// Infrastructure top-level domain - only one at present
	var infraRE = "arpa";

	// Generic top-level domains RE.
	var genericRE = 
		"aero|biz|com|coop|edu|gov|info|int|mil|museum|name|net|org|pro|travel|xxx|jobs|mobi|post";
	
	// Country Code top-level domains RE
	var ccRE = 
		"ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|" +
		"bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|" +
		"ec|ee|eg|er|es|et|fi|fj|fk|fm|fo|fr|ga|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|" +
		"hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|" +
		"lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|" +
		"mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|" +
		"ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sk|sl|sm|sn|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tm|tn|" +
		"to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw";

	// Build top-level domain RE
	var a = [];
	if (flags.allowInfra) { a.push(infraRE); }
	if (flags.allowGeneric) { a.push(genericRE); }
	if (flags.allowCC) { a.push(ccRE); }

	var tldRE = "";
	if (a.length > 0) {
		tldRE = "(" + a.join("|") + ")";
	}

	return tldRE;
}

/**
  Builds a RE that matches an IP Address.
  Supports 5 formats for IPv4: dotted decimal, dotted hex, dotted octal, decimal and hexadecimal.
  Supports 2 formats for Ipv6.

  @param flags  An object.  All flags are boolean with default = true.
    flags.allowDottedDecimal  Example, 207.142.131.235.  No zero padding.
    flags.allowDottedHex  Example, 0x18.0x11.0x9b.0x28.  Case insensitive.  Zero padding allowed.
    flags.allowDottedOctal  Example, 0030.0021.0233.0050.  Zero padding allowed.
    flags.allowDecimal  Example, 3482223595.  A decimal number between 0-4294967295.
    flags.allowHex  Example, 0xCF8E83EB.  Hexadecimal number between 0x0-0xFFFFFFFF.
      Case insensitive.  Zero padding allowed.
    flags.allowIPv6   IPv6 address written as eight groups of four hexadecimal digits.
    flags.allowHybrid   IPv6 address written as six groups of four hexadecimal digits
      followed by the usual 4 dotted decimal digit notation of IPv4. x:x:x:x:x:x:d.d.d.d

  @return  A string for a regular expression for an IP address.
*/
dojo.regexp.ipAddress = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.allowDottedDecimal != "boolean") { flags.allowDottedDecimal = true; }
	if (typeof flags.allowDottedHex != "boolean") { flags.allowDottedHex = true; }
	if (typeof flags.allowDottedOctal != "boolean") { flags.allowDottedOctal = true; }
	if (typeof flags.allowDecimal != "boolean") { flags.allowDecimal = true; }
	if (typeof flags.allowHex != "boolean") { flags.allowHex = true; }
	if (typeof flags.allowIPv6 != "boolean") { flags.allowIPv6 = true; }
	if (typeof flags.allowHybrid != "boolean") { flags.allowHybrid = true; }

	// decimal-dotted IP address RE.
	var dottedDecimalRE = 
		// Each number is between 0-255.  Zero padding is not allowed.
		"((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.){3}(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])";

	// dotted hex IP address RE.  Each number is between 0x0-0xff.  Zero padding is allowed, e.g. 0x00.
	var dottedHexRE = "(0[xX]0*[\\da-fA-F]?[\\da-fA-F]\\.){3}0[xX]0*[\\da-fA-F]?[\\da-fA-F]";

	// dotted octal IP address RE.  Each number is between 0000-0377.  
	// Zero padding is allowed, but each number must have at least 4 characters.
	var dottedOctalRE = "(0+[0-3][0-7][0-7]\\.){3}0+[0-3][0-7][0-7]";

	// decimal IP address RE.  A decimal number between 0-4294967295.  
	var decimalRE =  "(0|[1-9]\\d{0,8}|[1-3]\\d{9}|4[01]\\d{8}|42[0-8]\\d{7}|429[0-3]\\d{6}|" +
		"4294[0-8]\\d{5}|42949[0-5]\\d{4}|429496[0-6]\\d{3}|4294967[01]\\d{2}|42949672[0-8]\\d|429496729[0-5])";

	// hexadecimal IP address RE. 
	// A hexadecimal number between 0x0-0xFFFFFFFF. Case insensitive.  Zero padding is allowed.
	var hexRE = "0[xX]0*[\\da-fA-F]{1,8}";

	// IPv6 address RE. 
	// The format is written as eight groups of four hexadecimal digits, x:x:x:x:x:x:x:x,
	// where x is between 0000-ffff. Zero padding is optional. Case insensitive. 
	var ipv6RE = "([\\da-fA-F]{1,4}\\:){7}[\\da-fA-F]{1,4}";

	// IPv6/IPv4 Hybrid address RE. 
	// The format is written as six groups of four hexadecimal digits, 
	// followed by the 4 dotted decimal IPv4 format. x:x:x:x:x:x:d.d.d.d
	var hybridRE = "([\\da-fA-F]{1,4}\\:){6}" + 
		"((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])\\.){3}(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])";

	// Build IP Address RE
	var a = [];
	if (flags.allowDottedDecimal) { a.push(dottedDecimalRE); }
	if (flags.allowDottedHex) { a.push(dottedHexRE); }
	if (flags.allowDottedOctal) { a.push(dottedOctalRE); }
	if (flags.allowDecimal) { a.push(decimalRE); }
	if (flags.allowHex) { a.push(hexRE); }
	if (flags.allowIPv6) { a.push(ipv6RE); }
	if (flags.allowHybrid) { a.push(hybridRE); }

	var ipAddressRE = "";
	if (a.length > 0) {
		ipAddressRE = "(" + a.join("|") + ")";
	}

	return ipAddressRE;
}

/**
  Builds a RE that matches a host.
	A host is a domain name or an IP address, possibly followed by a port number.

  @param flags  An object.
    flags.allowIP  Allow an IP address for hostname.  Default is true.
    flags.allowLocal  Allow the host to be "localhost".  Default is false.
    flags.allowPort  Allow a port number to be present.  Default is true.
    flags in regexp.ipAddress can be applied.
    flags in regexp.tld can be applied.

  @return  A string for a regular expression for a host.
*/
dojo.regexp.host = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.allowIP != "boolean") { flags.allowIP = true; }
	if (typeof flags.allowLocal != "boolean") { flags.allowLocal = false; }
	if (typeof flags.allowPort != "boolean") { flags.allowPort = true; }

	// Domain names can not end with a dash.
	var domainNameRE = "([0-9a-zA-Z]([-0-9a-zA-Z]{0,61}[0-9a-zA-Z])?\\.)+" + dojo.regexp.tld(flags);

	// port number RE
	var portRE = ( flags.allowPort ) ? "(\\:" + dojo.regexp.integer({signed: false}) + ")?" : "";

	// build host RE
	var hostNameRE = domainNameRE;
	if (flags.allowIP) { hostNameRE += "|" +  dojo.regexp.ipAddress(flags); }
	if (flags.allowLocal) { hostNameRE += "|localhost"; }

	return "(" + hostNameRE + ")" + portRE;
}

/**
  Builds a regular expression that matches a URL.

  @param flags  An object.
    flags.scheme  Can be true, false, or [true, false]. 
      This means: required, not allowed, or match either one.
    flags in regexp.host can be applied.
    flags in regexp.ipAddress can be applied.
    flags in regexp.tld can be applied.

  @return  A string for a regular expression for a URL.
*/
dojo.regexp.url = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.scheme == "undefined") { flags.scheme = [true, false]; }

	// Scheme RE
	var protocalRE = dojo.regexp.buildGroupRE(flags.scheme,
		function(q) { if (q) { return "(https?|ftps?)\\://"; }  return ""; }
	);

	// Path and query and anchor RE
	var pathRE = "(/([^?#\\s/]+/)*)?([^?#\\s/]+(\\?[^?#\\s/]*)?(#[A-Za-z][\\w.:-]*)?)?";

	return (protocalRE + dojo.regexp.host(flags) + pathRE);
}

/**
  Builds a regular expression that matches an email address.

  @param flags  An object.
    flags.allowCruft  Allow address like <mailto:foo@yahoo.com>.  Default is false.
    flags in regexp.host can be applied.
    flags in regexp.ipAddress can be applied.
    flags in regexp.tld can be applied.

  @return  A string for a regular expression for an email address.
*/
dojo.regexp.emailAddress = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.allowCruft != "boolean") { flags.allowCruft = false; }
	flags.allowPort = false; // invalid in email addresses

	// user name RE - apostrophes are valid if there's not 2 in a row
	var usernameRE = "([\\da-z]+[-._+&'])*[\\da-z]+";

	// build emailAddress RE
	var emailAddressRE = usernameRE + "@" + dojo.regexp.host(flags);

	// Allow email addresses with cruft
	if ( flags.allowCruft ) {
		emailAddressRE = "<?(mailto\\:)?" + emailAddressRE + ">?";
	}

	return emailAddressRE;
}

/**
  Builds a regular expression that matches a list of email addresses.

  @param flags  An object.
    flags.listSeparator  The character used to separate email addresses.  Default is ";", ",", "\n" or " ".
    flags in regexp.emailAddress can be applied.
    flags in regexp.host can be applied.
    flags in regexp.ipAddress can be applied.
    flags in regexp.tld can be applied.

  @return  A string for a regular expression for an email address list.
*/
dojo.regexp.emailAddressList = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.listSeparator != "string") { flags.listSeparator = "\\s;,"; }

	// build a RE for an Email Address List
	var emailAddressRE = dojo.regexp.emailAddress(flags);
	var emailAddressListRE = "(" + emailAddressRE + "\\s*[" + flags.listSeparator + "]\\s*)*" + 
		emailAddressRE + "\\s*[" + flags.listSeparator + "]?\\s*";

	return emailAddressListRE;
}

/**
  Builds a regular expression that matches an integer.

  @param flags  An object.
    flags.signed  The leading plus-or-minus sign.  Can be true, false, or [true, false].
      Default is [true, false], (i.e. will match if it is signed or unsigned).
    flags.separator  The character used as the thousands separator.  Default is no separator.
      For more than one symbol use an array, e.g. [",", ""], makes ',' optional.

  @return  A string for a regular expression for an integer.
*/
dojo.regexp.integer = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.signed == "undefined") { flags.signed = [true, false]; }
	if (typeof flags.separator == "undefined") { flags.separator = ""; }

	// build sign RE
	var signRE = dojo.regexp.buildGroupRE(flags.signed,
		function(q) { if (q) { return "[-+]"; }  return ""; }
	);

	// number RE
	var numberRE = dojo.regexp.buildGroupRE(flags.separator,
		function(sep) { 
			if ( sep == "" ) { 
				return "(0|[1-9]\\d*)"; 
			}
			return "(0|[1-9]\\d{0,2}([" + sep + "]\\d{3})*)"; 
		}
	);
	var numberRE;

	// integer RE
	return (signRE + numberRE);
}

/**
  Builds a regular expression to match a real number in exponential notation.

  @param flags  An object.
    flags.places  The integer number of decimal places.
      If not given, the decimal part is optional and the number of places is unlimited.
    flags.decimal  A string for the character used as the decimal point.  Default is ".".
    flags.exponent  Express in exponential notation.  Can be true, false, or [true, false].
      Default is [true, false], (i.e. will match if the exponential part is present are not).
    flags.eSigned  The leading plus-or-minus sign on the exponent.  Can be true, false, 
      or [true, false].  Default is [true, false], (i.e. will match if it is signed or unsigned).
    flags in regexp.integer can be applied.

  @return  A string for a regular expression for a real number.
*/
dojo.regexp.realNumber = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.places != "number") { flags.places = Infinity; }
	if (typeof flags.decimal != "string") { flags.decimal = "."; }
	if (typeof flags.exponent == "undefined") { flags.exponent = [true, false]; }
	if (typeof flags.eSigned == "undefined") { flags.eSigned = [true, false]; }

	// integer RE
	var integerRE = dojo.regexp.integer(flags);

	// decimal RE
	var decimalRE = "";
	if ( flags.places == Infinity) { 
		decimalRE = "(\\" + flags.decimal + "\\d+)?"; 
	}
	else if ( flags.places > 0) { 
		decimalRE = "\\" + flags.decimal + "\\d{" + flags.places + "}"; 
	}

	// exponent RE
	var exponentRE = dojo.regexp.buildGroupRE(flags.exponent,
		function(q) { 
			if (q) { return "([eE]" + dojo.regexp.integer({signed: flags.eSigned}) + ")"; }
			return ""; 
		}
	);

	// real number RE
	return (integerRE + decimalRE + exponentRE);
}

/**
  Builds a regular expression to match a monetary value.

  @param flags  An object.
    flags.signed  The leading plus-or-minus sign.  Can be true, false, or [true, false].
      Default is [true, false], (i.e. will match if it is signed or unsigned).
    flags.symbol  A currency symbol such as Yen "�", Pound "�", or the Euro sign "�".  
      Default is "$".  For more than one symbol use an array, e.g. ["$", ""], makes $ optional.
    flags.placement  The symbol can come "before" the number or "after".  Default is "before".
    flags.separator  The character used as the thousands separator. The default is ",".
    flags.cents  The two decimal places for cents.  Can be true, false, or [true, false].
      Default is [true, false], (i.e. will match if cents are present are not).
    flags.decimal  A string for the character used as the decimal point.  Default is ".".

  @return  A string for a regular expression for a monetary value.
*/
dojo.regexp.currency = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.signed == "undefined") { flags.signed = [true, false]; }
	if (typeof flags.symbol == "undefined") { flags.symbol = "$"; }
	if (typeof flags.placement != "string") { flags.placement = "before"; }
	if (typeof flags.separator != "string") { flags.separator = ","; }
	if (typeof flags.cents == "undefined") { flags.cents = [true, false]; }
	if (typeof flags.decimal != "string") { flags.decimal = "."; }

	// build sign RE
	var signRE = dojo.regexp.buildGroupRE(flags.signed,
		function(q) { if (q) { return "[-+]"; }  return ""; }
	);

	// build symbol RE
	var symbolRE = dojo.regexp.buildGroupRE(flags.symbol,
		function(symbol) { 
			// escape all special characters
			return "\\s?" + symbol.replace( /([.$?*!=:|\\\/^])/g, "\\$1") + "\\s?";
		}
	);

	// number RE
	var numberRE = dojo.regexp.integer( {signed: false, separator: flags.separator} );

	// build cents RE
	var centsRE = dojo.regexp.buildGroupRE(flags.cents,
		function(q) { if (q) { return "(\\" + flags.decimal + "\\d\\d)"; }  return ""; }
	);

	// build currency RE
	var currencyRE;
	if (flags.placement == "before") {
		currencyRE = signRE + symbolRE + numberRE + centsRE;
	}
	else {
		currencyRE = signRE + numberRE + centsRE + symbolRE;
	}

	return currencyRE;
}

/**
  A regular expression to match US state and territory abbreviations.

  @param flags  An object.
    flags.allowTerritories  Allow Guam, Puerto Rico, etc.  Default is true.
    flags.allowMilitary  Allow military 'states', e.g. Armed Forces Europe (AE).  Default is true.

  @return  A string for a regular expression for a US state.
*/
dojo.regexp.us.state = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.allowTerritories != "boolean") { flags.allowTerritories = true; }
	if (typeof flags.allowMilitary != "boolean") { flags.allowMilitary = true; }

	// state RE
	var statesRE = 
		"AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|" + 
		"NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY";

	// territories RE
	var territoriesRE = "AS|FM|GU|MH|MP|PW|PR|VI";

	// military states RE
	var militaryRE = "AA|AE|AP";

	// Build states and territories RE
	if (flags.allowTerritories) { statesRE += "|" + territoriesRE; }
	if (flags.allowMilitary) { statesRE += "|" + militaryRE; }

	return "(" + statesRE + ")";
}

/**
  Builds a regular expression to match any International format for time.
  The RE can match one format or one of multiple formats.

  Format
  h        12 hour, no zero padding.
  hh       12 hour, has leading zero.
  H        24 hour, no zero padding.
  HH       24 hour, has leading zero.
  m        minutes, no zero padding.
  mm       minutes, has leading zero.
  s        seconds, no zero padding.
  ss       seconds, has leading zero.
  t        am or pm, case insensitive.
  All other characters must appear literally in the expression.

  Example
    "h:m:s t"  ->   2:5:33 PM
    "HH:mm:ss" ->  14:05:33

  @param flags  An object.
    flags.format  A string or an array of strings.  Default is "h:mm:ss t".
    flags.amSymbol  The symbol used for AM.  Default is "AM".
    flags.pmSymbol  The symbol used for PM.  Default is "PM".

  @return  A string for a regular expression for a time value.
*/
dojo.regexp.time = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.format == "undefined") { flags.format = "h:mm:ss t"; }
	if (typeof flags.amSymbol != "string") { flags.amSymbol = "AM"; }
	if (typeof flags.pmSymbol != "string") { flags.pmSymbol = "PM"; }

	// Converts a time format to a RE
	var timeRE = function(format) {
		// escape all special characters
		format = format.replace( /([.$?*!=:|{}\(\)\[\]\\\/^])/g, "\\$1");
		var amRE = flags.amSymbol.replace( /([.$?*!=:|{}\(\)\[\]\\\/^])/g, "\\$1");
		var pmRE = flags.pmSymbol.replace( /([.$?*!=:|{}\(\)\[\]\\\/^])/g, "\\$1");

		// replace tokens with Regular Expressions
		format = format.replace("hh", "(0[1-9]|1[0-2])");
		format = format.replace("h", "([1-9]|1[0-2])");
		format = format.replace("HH", "([01][0-9]|2[0-3])");
		format = format.replace("H", "([0-9]|1[0-9]|2[0-3])");
		format = format.replace("mm", "([0-5][0-9])");
		format = format.replace("m", "([1-5][0-9]|[0-9])");
		format = format.replace("ss", "([0-5][0-9])");
		format = format.replace("s", "([1-5][0-9]|[0-9])");
		format = format.replace("t", "\\s?(" + amRE + "|" + pmRE + ")\\s?" );

		return format;
	};

	// build RE for multiple time formats
	return dojo.regexp.buildGroupRE(flags.format, timeRE);
}

/**
  Builds a regular expression to match any sort of number based format.
  Use it for phone numbers, social security numbers, zip-codes, etc.
  The RE can match one format or one of multiple formats.

  Format
    #        Stands for a digit, 0-9.
    ?        Stands for an optional digit, 0-9 or nothing.
    All other characters must appear literally in the expression.

  Example   
    "(###) ###-####"       ->   (510) 542-9742
    "(###) ###-#### x#???" ->   (510) 542-9742 x153
    "###-##-####"          ->   506-82-1089       i.e. social security number
    "#####-####"           ->   98225-1649        i.e. zip code

  @param flags  An object.
    flags.format  A string or an Array of strings for multiple formats.
  @return  A string for a regular expression for the number format(s).
*/
dojo.regexp.numberFormat = function(flags) {
	// assign default values to missing paramters
	flags = (typeof flags == "object") ? flags : {};
	if (typeof flags.format == "undefined") { flags.format = "###-###-####"; }

	// Converts a number format to RE.
	var digitRE = function(format) {
		// escape all special characters, except '?'
		format = format.replace( /([.$*!=:|{}\(\)\[\]\\\/^])/g, "\\$1");

		// Now replace '?' with Regular Expression
		format = format.replace(/\?/g, "\\d?");

		// replace # with Regular Expression
		format = format.replace(/#/g, "\\d");

		return format;
	};

	// build RE for multiple number formats
	return dojo.regexp.buildGroupRE(flags.format, digitRE);
}


/**
  This is basically a utility function used by some of the RE generators.
  Builds a regular expression that groups subexpressions.
  The subexpressions are constructed by the function, re, in the second parameter.
  re builds one subexpression for each elem in the array a, in the first parameter.

  @param a  A single value or an array of values.
  @param re  A function.  Takes one parameter and converts it to a regular expression. 
  @return  A string for a regular expression that groups all the subexpressions.
*/
dojo.regexp.buildGroupRE = function(a, re) {

	// case 1: a is a single value.
	if ( !( a instanceof Array ) ) { 
		return re(a);
	}

	// case 2: a is an array
	var b = [];
	for (var i = 0; i < a.length; i++) {
		// convert each elem to a RE
		b.push(re(a[i]));
	}

	 // join the REs as alternatives in a RE group.
	return "(" + b.join("|") + ")";
}
