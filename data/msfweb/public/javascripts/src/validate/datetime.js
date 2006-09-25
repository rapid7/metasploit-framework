/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.validate.datetime");
dojo.require("dojo.validate.common");

/**
  Validates a time value in any International format.
  The value can be validated against one format or one of multiple formats.

  Format
  h        12 hour, no zero padding.
  hh       12 hour, has leading zero.
  H        24 hour, no zero padding.
  HH       24 hour, has leading zero.
  m        minutes, no zero padding.
  mm       minutes, has leading zero.
  s        seconds, no zero padding.
  ss       seconds, has leading zero.
  All other characters must appear literally in the expression.

  Example
    "h:m:s t"  ->   2:5:33 PM
    "HH:mm:ss" ->  14:05:33

  @param value  A string.
  @param flags  An object.
    flags.format  A string or an array of strings.  Default is "h:mm:ss t".
    flags.amSymbol  The symbol used for AM.  Default is "AM".
    flags.pmSymbol  The symbol used for PM.  Default is "PM".
  @return  true or false
*/
dojo.validate.isValidTime = function(value, flags) {
	var re = new RegExp("^" + dojo.regexp.time(flags) + "$", "i");
	return re.test(value);
}

/**
  Validates 12-hour time format.
  Zero-padding is not allowed for hours, required for minutes and seconds.
  Seconds are optional.

  @param value  A string.
  @return  true or false
*/
dojo.validate.is12HourTime = function(value) {
	return dojo.validate.isValidTime(value, {format: ["h:mm:ss t", "h:mm t"]});
}

/**
  Validates 24-hour military time format.
  Zero-padding is required for hours, minutes, and seconds.
  Seconds are optional.

  @param value  A string.
  @return  true or false
*/
dojo.validate.is24HourTime = function(value) {
	return dojo.validate.isValidTime(value, {format: ["HH:mm:ss", "HH:mm"]} );
}

/**
  Returns true if the date conforms to the format given and is a valid date. Otherwise returns false.

  @param dateValue  A string for the date.
  @param format  A string, default is  "MM/DD/YYYY".
  @return  true or false

  Accepts any type of format, including ISO8601.
  All characters in the format string are treated literally except the following tokens:

  YYYY - matches a 4 digit year
  M - matches a non zero-padded month
  MM - matches a zero-padded month
  D -  matches a non zero-padded date
  DD -  matches a zero-padded date
  DDD -  matches an ordinal date, 001-365, and 366 on leapyear
  ww - matches week of year, 01-53
  d - matches day of week, 1-7

  Examples: These are all today's date.

  Date          Format
  2005-W42-3    YYYY-Www-d
  2005-292      YYYY-DDD
  20051019      YYYYMMDD
  10/19/2005    M/D/YYYY
  19.10.2005    D.M.YYYY
*/
dojo.validate.isValidDate = function(dateValue, format) {
	// Default is the American format
	if (typeof format == "object" && typeof format.format == "string"){ format = format.format; }
	if (typeof format != "string") { format = "MM/DD/YYYY"; }

	// Create a literal regular expression based on format
	var reLiteral = format.replace(/([$^.*+?=!:|\/\\\(\)\[\]\{\}])/g, "\\$1");

	// Convert all the tokens to RE elements
	reLiteral = reLiteral.replace( "YYYY", "([0-9]{4})" );
	reLiteral = reLiteral.replace( "MM", "(0[1-9]|10|11|12)" );
	reLiteral = reLiteral.replace( "M", "([1-9]|10|11|12)" );
	reLiteral = reLiteral.replace( "DDD", "(00[1-9]|0[1-9][0-9]|[12][0-9][0-9]|3[0-5][0-9]|36[0-6])" );
	reLiteral = reLiteral.replace( "DD", "(0[1-9]|[12][0-9]|30|31)" );
	reLiteral = reLiteral.replace( "D", "([1-9]|[12][0-9]|30|31)" );
	reLiteral = reLiteral.replace( "ww", "(0[1-9]|[1-4][0-9]|5[0-3])" );
	reLiteral = reLiteral.replace( "d", "([1-7])" );

	// Anchor pattern to begining and end of string
	reLiteral = "^" + reLiteral + "$";

	// Dynamic RE that parses the original format given
	var re = new RegExp(reLiteral);
	
	// Test if date is in a valid format
	if (!re.test(dateValue))  return false;

	// Parse date to get elements and check if date is valid
	// Assume valid values for date elements not given.
	var year = 0, month = 1, date = 1, dayofyear = 1, week = 1, day = 1;

	// Capture tokens
	var tokens = format.match( /(YYYY|MM|M|DDD|DD|D|ww|d)/g );

	// Capture date values
	var values = re.exec(dateValue);

	// Match up tokens with date values
	for (var i = 0; i < tokens.length; i++) {
		switch (tokens[i]) {
		case "YYYY":
			year = Number(values[i+1]); break;
		case "M":
		case "MM":
			month = Number(values[i+1]); break;
		case "D":
		case "DD":
			date = Number(values[i+1]); break;
		case "DDD":
			dayofyear = Number(values[i+1]); break;
		case "ww":
			week = Number(values[i+1]); break;
		case "d":
			day = Number(values[i+1]); break;
		}
	}

	// Leap years are divisible by 4, but not by 100, unless by 400
	var leapyear = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));

	// 31st of a month with 30 days
	if (date == 31 && (month == 4 || month == 6 || month == 9 || month == 11)) return false; 

	// February 30th or 31st
	if (date >= 30 && month == 2) return false; 

	// February 29th outside a leap year
	if (date == 29 && month == 2 && !leapyear) return false; 
	if (dayofyear == 366 && !leapyear)  return false;

	return true;
}
