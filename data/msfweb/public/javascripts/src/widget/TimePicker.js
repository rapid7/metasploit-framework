/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.TimePicker");
dojo.provide("dojo.widget.TimePicker.util");
dojo.require("dojo.widget.DomWidget");
dojo.require("dojo.date");

dojo.widget.TimePicker = function(){
	dojo.widget.Widget.call(this);
	this.widgetType = "TimePicker";
	this.isContainer = false;
	// the following aliases prevent breaking people using 0.2.x
	this.toRfcDateTime = dojo.widget.TimePicker.util.toRfcDateTime;
	this.fromRfcDateTime = dojo.widget.TimePicker.util.fromRfcDateTime;
	this.toAmPmHour = dojo.widget.TimePicker.util.toAmPmHour;
	this.fromAmPmHour = dojo.widget.TimePicker.util.fromAmPmHour;
}

dojo.inherits(dojo.widget.TimePicker, dojo.widget.Widget);
dojo.widget.tags.addParseTreeHandler("dojo:timepicker");

dojo.requireAfterIf("html", "dojo.widget.html.TimePicker");

dojo.widget.TimePicker.util = new function() {
	// utility functions
	this.toRfcDateTime = function(jsDate) {
		if(!jsDate) {
			jsDate = new Date();
		}
		return dojo.date.format(jsDate, "%Y-%m-%dT%H:%M:00%z");
	}

	this.fromRfcDateTime = function(rfcDate, useDefaultMinutes, isAnyTime) {
		var tempDate = new Date();
		if(!rfcDate || rfcDate.indexOf("T")==-1) {
			if(useDefaultMinutes) {
				tempDate.setMinutes(Math.floor(tempDate.getMinutes()/5)*5);
			} else {
				tempDate.setMinutes(0);
			}
		} else {
			var tempTime = rfcDate.split("T")[1].split(":");
			// fullYear, month, date
			var tempDate = new Date();
			tempDate.setHours(tempTime[0]);
			tempDate.setMinutes(tempTime[1]);
		}
		return tempDate;
	}

	this.toAmPmHour = function(hour) {
		var amPmHour = hour;
		var isAm = true;
		if (amPmHour == 0) {
			amPmHour = 12;
		} else if (amPmHour>12) {
			amPmHour = amPmHour - 12;
			isAm = false;
		} else if (amPmHour == 12) {
			isAm = false;
		}
		return [amPmHour, isAm];
	}

	this.fromAmPmHour = function(amPmHour, isAm) {
		var hour = parseInt(amPmHour, 10);
		if(isAm && hour == 12) {
			hour = 0;
		} else if (!isAm && hour<12) {
			hour = hour + 12;
		}
		return hour;
	}
}
