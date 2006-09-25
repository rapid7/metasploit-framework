/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.iCalendar");
dojo.require("dojo.text.textDirectory");
dojo.require("dojo.date");
dojo.require("dojo.lang");


dojo.iCalendar.fromText =  function (/* string */text) {
	// summary
	// Parse text of an iCalendar and return an array of iCalendar objects

	var properties = dojo.textDirectoryTokeniser.tokenise(text);
	var calendars = [];

	//dojo.debug("Parsing iCal String");
	for (var i = 0, begun = false; i < properties.length; i++) {
		var prop = properties[i];
		if (!begun) {
			if (prop.name == 'BEGIN' && prop.value == 'VCALENDAR') {
				begun = true;
				var calbody = [];
			}
		} else if (prop.name == 'END' && prop.value == 'VCALENDAR') {
			calendars.push(new dojo.iCalendar.VCalendar(calbody));
			begun = false;
		} else {
			calbody.push(prop);
		}
	}
	return /* array */calendars;
}


dojo.iCalendar.Component = function (/* string */ body ) {
	// summary
	// A component is the basic container of all this stuff. 

	if (!this.name) {
		this.name = "COMPONENT"
	}

	this.properties = [];
	this.components = [];

	if (body) {
		for (var i = 0, context = ''; i < body.length; i++) {
			if (context == '') {
				if (body[i].name == 'BEGIN') {
					context = body[i].value;
					var childprops = [];
				} else {
					this.addProperty(new dojo.iCalendar.Property(body[i]));
				}
			} else if (body[i].name == 'END' && body[i].value == context) {
				if (context=="VEVENT") {
					this.addComponent(new dojo.iCalendar.VEvent(childprops));
				} else if (context=="VTIMEZONE") {
					this.addComponent(new dojo.iCalendar.VTimeZone(childprops));
				} else if (context=="VTODO") {
					this.addComponent(new dojo.iCalendar.VTodo(childprops));
				} else if (context=="VJOURNAL") {
					this.addComponent(new dojo.iCalendar.VJournal(childprops));
				} else if (context=="VFREEBUSY") {
					this.addComponent(new dojo.iCalendar.VFreeBusy(childprops));
				} else if (context=="STANDARD") {
					this.addComponent(new dojo.iCalendar.Standard(childprops));
				} else if (context=="DAYLIGHT") {
					this.addComponent(new dojo.iCalendar.Daylight(childprops));
				} else if (context=="VALARM") {
					this.addComponent(new dojo.iCalendar.VAlarm(childprops));
				}else {
					dojo.unimplemented("dojo.iCalendar." + context);
				}
				context = '';
			} else {
				childprops.push(body[i]);
			}
		}

		if (this._ValidProperties) {
			this.postCreate();
		}
	}
}

dojo.lang.extend(dojo.iCalendar.Component, {

	addProperty: function (prop) {
		// summary
		// push a new property onto a component.
		this.properties.push(prop);
		this[prop.name.toLowerCase()] = prop;
	},

	addComponent: function (prop) {
		// summary
		// add a component to this components list of children.
		this.components.push(prop);
	},

	postCreate: function() {
		for (var x=0; x<this._ValidProperties.length; x++) {
			var evtProperty = this._ValidProperties[x];
			var found = false;
	
			for (var y=0; y<this.properties.length; y++) {	
				var prop = this.properties[y];
				var propName = prop.name.toLowerCase();
				if (dojo.lang.isArray(evtProperty)) {

					var alreadySet = false;
					for (var z=0; z<evtProperty.length; z++) {
						var evtPropertyName = evtProperty[z].name.toLowerCase();
						if((this[evtPropertyName])  && (evtPropertyName != propName )) {
							alreadySet=true;
						} 
					}
					if (!alreadySet) {
						this[propName] = prop;
					}
				} else {
					if (propName == evtProperty.name.toLowerCase()) {
						found = true;
						if (evtProperty.occurance == 1){
							this[propName] = prop;
						} else {
							found = true;
							if (!dojo.lang.isArray(this[propName])) {
							 	this[propName] = [];
							}
							this[propName].push(prop);
						}
					}
				}
			}

			if (evtProperty.required && !found) {	
				dojo.debug("iCalendar - " + this.name + ": Required Property not found: " + evtProperty.name);
			}
		}

		// parse any rrules		
		if (dojo.lang.isArray(this.rrule)) {
			for(var x=0; x<this.rrule.length; x++) {
				var rule = this.rrule[x].value;

				//add a place to cache dates we have checked for recurrance
				this.rrule[x].cache = function() {};
				
				var temp = rule.split(";");
				for (var y=0; y<temp.length; y++) {
					var pair = temp[y].split("=");
					var key = pair[0].toLowerCase();
					var val = pair[1];

					if ((key == "freq") || (key=="interval") || (key=="until")) {
						this.rrule[x][key]= val;
					} else {
						var valArray = val.split(",");
						this.rrule[x][key] = valArray; 
					}
				}	
			}
			this.recurring = true;
		}

	}, 

	toString: function () {
		// summary
		// output a string representation of this component.
		return "[iCalendar.Component; " + this.name + ", " + this.properties.length +
			" properties, " + this.components.length + " components]";
	}
});

dojo.iCalendar.Property = function (prop) {
	// summary
	// A single property of a component.

	// unpack the values
	this.name = prop.name;
	this.group = prop.group;
	this.params = prop.params;
	this.value = prop.value;

}

dojo.lang.extend(dojo.iCalendar.Property, {
	toString: function () {	
		// summary
		// output a string reprensentation of this component.
		return "[iCalenday.Property; " + this.name + ": " + this.value + "]";
	}
});

// This is just a little helper function for the Component Properties
var _P = function (n, oc, req) {
	return {name: n, required: (req) ? true : false,
		occurance: (oc == '*' || !oc) ? -1 : oc}
}

/*
 * VCALENDAR
 */

dojo.iCalendar.VCalendar = function (/* string */ calbody) {
	// summary
	// VCALENDAR Component

	this.name = "VCALENDAR";
	this.recurring = [];
	this.nonRecurringEvents = function(){};
	dojo.iCalendar.Component.call(this, calbody);
}

dojo.inherits(dojo.iCalendar.VCalendar, dojo.iCalendar.Component);

dojo.lang.extend(dojo.iCalendar.VCalendar, {

	addComponent: function (prop) {
		// summary
		// add component to the calenadar that makes it easy to pull them out again later.
		this.components.push(prop);
		if (prop.name.toLowerCase() == "vevent") {
			if (prop.rrule) {
				this.recurring.push(prop);
			} else {
				var startDate = prop.getDate();
				var month = startDate.getMonth() + 1;
				var dateString= month + "-" + startDate.getDate() + "-" + startDate.getFullYear();
				if (!dojo.lang.isArray(this[dateString])) {
					this.nonRecurringEvents[dateString] = [];
				}
				this.nonRecurringEvents[dateString].push(prop);
			}
		}
	},

	preComputeRecurringEvents: function(until) {
		var calculatedEvents = function(){};

		for(var x=0; x<this.recurring.length; x++) {
			var dates = this.recurring[x].getDates(until);
			for (var y=0; y<dates.length;y++) {
				var month = dates[y].getMonth() + 1;
				var dateStr = month + "-" + dates[y].getDate() + "-" + dates[y].getFullYear();
				if (!dojo.lang.isArray(calculatedEvents[dateStr])) {
					calculatedEvents[dateStr] = [];
				}

				if (!dojo.lang.inArray(calculatedEvents[dateStr], this.recurring[x])) { 
					calculatedEvents[dateStr].push(this.recurring[x]);
				} 
			}
		}
		this.recurringEvents = calculatedEvents;
	
	},

	getEvents: function(/* Date */ date) {
		// summary
		// Gets all events occuring on a particular date
		var events = [];
		var recur = [];
		var nonRecur = [];
		var month = date.getMonth() + 1;
		var dateStr= month + "-" + date.getDate() + "-" + date.getFullYear();
		if (dojo.lang.isArray(this.nonRecurringEvents[dateStr])) {
			nonRecur= this.nonRecurringEvents[dateStr];
			dojo.debug("Number of nonRecurring Events: " + nonRecur.length);
		} 
		

		if (dojo.lang.isArray(this.recurringEvents[dateStr])) {
			recur= this.recurringEvents[dateStr];
		} 

		events = recur.concat(nonRecur);

		if (events.length > 0) {
			return events;
		} 

		return null;			
	}
});

/*
 * STANDARD
 */

var StandardProperties = [
	_P("dtstart", 1, true), _P("tzoffsetto", 1, true), _P("tzoffsetfrom", 1, true),
	_P("comment"), _P("rdate"), _P("rrule"), _P("tzname")
];


dojo.iCalendar.Standard = function (/* string */ body) {
	// summary
	// STANDARD Component

	this.name = "STANDARD";
	this._ValidProperties = StandardProperties;
	dojo.iCalendar.Component.call(this, body);
}

dojo.inherits(dojo.iCalendar.Standard, dojo.iCalendar.Component);

/*
 * DAYLIGHT
 */

var DaylightProperties = [
	_P("dtstart", 1, true), _P("tzoffsetto", 1, true), _P("tzoffsetfrom", 1, true),
	_P("comment"), _P("rdate"), _P("rrule"), _P("tzname")
];

dojo.iCalendar.Daylight = function (/* string */ body) {
	// summary
	// Daylight Component
	this.name = "DAYLIGHT";
	this._ValidProperties = DaylightProperties;
	dojo.iCalendar.Component.call(this, body);
}

dojo.inherits(dojo.iCalendar.Daylight, dojo.iCalendar.Component);

/*
 * VEVENT
 */

var VEventProperties = [
	// these can occur once only
	_P("class", 1), _P("created", 1), _P("description", 1), _P("dtstart", 1),
	_P("geo", 1), _P("last-mod", 1), _P("location", 1), _P("organizer", 1),
	_P("priority", 1), _P("dtstamp", 1), _P("seq", 1), _P("status", 1),
	_P("summary", 1), _P("transp", 1), _P("uid", 1), _P("url", 1), _P("recurid", 1),
	// these two are exclusive
	[_P("dtend", 1), _P("duration", 1)],
	// these can occur many times over
	_P("attach"), _P("attendee"), _P("categories"), _P("comment"), _P("contact"),
	_P("exdate"), _P("exrule"), _P("rstatus"), _P("related"), _P("resources"),
	_P("rdate"), _P("rrule")
];

dojo.iCalendar.VEvent = function (/* string */ body) {
	// summary 
	// VEVENT Component
	this._ValidProperties = VEventProperties;
	this.name = "VEVENT";
	dojo.iCalendar.Component.call(this, body);
	this.recurring = false;
	this.startDate = dojo.date.fromIso8601(this.dtstart.value);
}

dojo.inherits(dojo.iCalendar.VEvent, dojo.iCalendar.Component);

dojo.lang.extend(dojo.iCalendar.VEvent, {
		getDates: function(until) {
			var dtstart = this.getDate();

			var recurranceSet = [];
			var weekdays=["su","mo","tu","we","th","fr","sa"];
			var order = { 
				"daily": 1, "weekly": 2, "monthly": 3, "yearly": 4,
				"byday": 1, "bymonthday": 1, "byweekno": 2, "bymonth": 3, "byyearday": 4};

			// expand rrules into the recurrance 
			for (var x=0; x<this.rrule.length; x++) {
				var rrule = this.rrule[x];
				var freq = rrule.freq.toLowerCase();
				var interval = 1;

				if (rrule.interval > interval) {
					interval = rrule.interval;
				}

				var set = [];
				var freqInt = order[freq];

				if (rrule.until) {
					var tmpUntil = dojo.date.fromIso8601(rrule.until);
				} else {
					var tmpUntil = until
				}

				if (tmpUntil > until) {
					tmpUntil = until
				}


				if (dtstart<tmpUntil) {

					var expandingRules = function(){};
					var cullingRules = function(){};
					expandingRules.length=0;
					cullingRules.length =0;

					switch(freq) {
						case "yearly":
							var nextDate = new Date(dtstart);
							set.push(nextDate);
							while(nextDate < tmpUntil) {
								nextDate.setYear(nextDate.getFullYear()+interval);
								tmpDate = new Date(nextDate);
								if(tmpDate < tmpUntil) {
									set.push(tmpDate);
								}
							}
							break;
						case "monthly":
							nextDate = new Date(dtstart);
							set.push(nextDate);
							while(nextDate < tmpUntil) {
								nextDate.setMonth(nextDate.getMonth()+interval);
								var tmpDate = new Date(nextDate);
								if (tmpDate < tmpUntil) {
									set.push(tmpDate);
								}
							}
							break;
						case "weekly":
							nextDate = new Date(dtstart);
							set.push(nextDate);
							while(nextDate < tmpUntil) {
								nextDate.setDate(nextDate.getDate()+(7*interval));
								var tmpDate = new Date(nextDate);
								if (tmpDate < tmpUntil) {
									set.push(tmpDate);
								}
							}
							break;	
						case "daily":
							nextDate = new Date(dtstart);
							set.push(nextDate);
							while(nextDate < tmpUntil) {
								nextDate.setDate(nextDate.getDate()+interval);
								var tmpDate = new Date(nextDate);
								if (tmpDate < tmpUntil) {
									set.push(tmpDate);
								}
							}
							break;
	
					}

					if ((rrule["bymonth"]) && (order["bymonth"]<freqInt))	{
						for (var z=0; z<rrule["bymonth"].length; z++) {
							if (z==0) {
								for (var zz=0; zz < set.length; zz++) {
									set[zz].setMonth(rrule["bymonth"][z]-1);
								}
							} else {
								var subset=[];
								for (var zz=0; zz < set.length; zz++) {
									var newDate = new Date(set[zz]);
									newDate.setMonth(rrule[z]);
									subset.push(newDate);
								}
								tmp = set.concat(subset);
								set = tmp;
							}
						}
					}

					
					// while the spec doesn't prohibit it, it makes no sense to have a bymonth and a byweekno at the same time
					// and if i'm wrong then i don't know how to apply that rule.  This is also documented elsewhere on the web
					if (rrule["byweekno"] && !rrule["bymonth"]) {	
						dojo.debug("TODO: no support for byweekno yet");
					}


					// while the spec doesn't prohibit it, it makes no sense to have a bymonth and a byweekno at the same time
					// and if i'm wrong then i don't know how to apply that rule.  This is also documented elsewhere on the web
					if (rrule["byyearday"] && !rrule["bymonth"] && !rrule["byweekno"] ) {	
						if (rrule["byyearday"].length > 1) {
							var regex = "([+-]?)([0-9]{1,3})";
							for (var z=1; x<rrule["byyearday"].length; z++) {
								var regexResult = rrule["byyearday"][z].match(regex);
								if (z==1) {
									for (var zz=0; zz < set.length; zz++) {
										if (regexResult[1] == "-") {
											dojo.date.setDayOfYear(set[zz],366-regexResult[2]);
										} else {
											dojo.date.setDayOfYear(set[zz],regexResult[2]);
										}
									}
								}	else {
									var subset=[];
									for (var zz=0; zz < set.length; zz++) {
										var newDate = new Date(set[zz]);
										if (regexResult[1] == "-") {
											dojo.date.setDayOfYear(newDate,366-regexResult[2]);
										} else {
											dojo.date.setDayOfYear(newDate,regexResult[2]);
										}
										subset.push(newDate);
									}
									tmp = set.concat(subset);
									set = tmp;
								}
							}
						}
					}

					if (rrule["bymonthday"]  && (order["bymonthday"]<freqInt)) {	
						if (rrule["bymonthday"].length > 0) {
							var regex = "([+-]?)([0-9]{1,3})";
							for (var z=0; z<rrule["bymonthday"].length; z++) {
								var regexResult = rrule["bymonthday"][z].match(regex);
								if (z==0) {
									for (var zz=0; zz < set.length; zz++) {
										if (regexResult[1] == "-") {
											if (regexResult[2] < dojo.date.getDaysInMonth(set[zz])) {
												set[zz].setDate(dojo.date.getDaysInMonth(set[zz]) - regexResult[2]);
											}
										} else {
											if (regexResult[2] < dojo.date.getDaysInMonth(set[zz])) {
												set[zz].setDate(regexResult[2]);
											}
										}
									}
								}	else {
									var subset=[];
									for (var zz=0; zz < set.length; zz++) {
										var newDate = new Date(set[zz]);
										if (regexResult[1] == "-") {
											if (regexResult[2] < dojo.date.getDaysInMonth(set[zz])) {
												newDate.setDate(dojo.date.getDaysInMonth(set[zz]) - regexResult[2]);
											}
										} else {
											if (regexResult[2] < dojo.date.getDaysInMonth(set[zz])) {
												newDate.setDate(regexResult[2]);
											}
										}
										subset.push(newDate);
									}
									tmp = set.concat(subset);
									set = tmp;
								}
							}
						}
					}

					if (rrule["byday"]  && (order["byday"]<freqInt)) {	
						if (rrule["bymonth"]) {
							if (rrule["byday"].length > 0) {
								var regex = "([+-]?)([0-9]{0,1}?)([A-Za-z]{1,2})";
								for (var z=0; z<rrule["byday"].length; z++) {
									var regexResult = rrule["byday"][z].match(regex);
									var occurance = regexResult[2];
									var day = regexResult[3].toLowerCase();


									if (z==0) {
										for (var zz=0; zz < set.length; zz++) {
											if (regexResult[1] == "-") {
												//find the nth to last occurance of date 
												var numDaysFound = 0;
												var lastDayOfMonth = dojo.date.getDaysInMonth(set[zz]);
												var daysToSubtract = 1;
												set[zz].setDate(lastDayOfMonth); 
												if (weekdays[set[zz].getDay()] == day) {
													numDaysFound++;
													daysToSubtract=7;
												}
												daysToSubtract = 1;
												while (numDaysFound < occurance) {
													set[zz].setDate(set[zz].getDate()-daysToSubtract);	
													if (weekdays[set[zz].getDay()] == day) {
														numDaysFound++;
														daysToSubtract=7;	
													}
												}
											} else {
												if (occurance) {
													var numDaysFound=0;
													set[zz].setDate(1);
													var daysToAdd=1;

													if(weekdays[set[zz].getDay()] == day) {
														numDaysFound++;
														daysToAdd=7;
													}

													while(numDaysFound < occurance) {
														set[zz].setDate(set[zz].getDate()+daysToAdd);
														if(weekdays[set[zz].getDay()] == day) {
															numDaysFound++;
															daysToAdd=7;
														}
													}
												} else {
													//we're gonna expand here to add a date for each of the specified days for each month
													var numDaysFound=0;
													var subset = [];

													lastDayOfMonth = new Date(set[zz]);
													var daysInMonth = dojo.date.getDaysInMonth(set[zz]);
													lastDayOfMonth.setDate(daysInMonth);

													set[zz].setDate(1);
												
													if (weekdays[set[zz].getDay()] == day) {
														numDaysFound++;
													}
													var tmpDate = new Date(set[zz]);
													daysToAdd = 1;
													while(tmpDate.getDate() < lastDayOfMonth) {
														if (weekdays[tmpDate.getDay()] == day) {
															numDaysFound++;
															if (numDaysFound==1) {
																set[zz] = tmpDate;
															} else {
																subset.push(tmpDate);
																tmpDate = new Date(tmpDate);
																daysToAdd=7;	
																tmpDate.setDate(tmpDate.getDate() + daysToAdd);
															}
														} else {
															tmpDate.setDate(tmpDate.getDate() + daysToAdd);
														}
													}
													var t = set.concat(subset);
													set = t; 
												}
											}
										}
									}	else {
										var subset=[];
										for (var zz=0; zz < set.length; zz++) {
											var newDate = new Date(set[zz]);
											if (regexResult[1] == "-") {
												if (regexResult[2] < dojo.date.getDaysInMonth(set[zz])) {
													newDate.setDate(dojo.date.getDaysInMonth(set[zz]) - regexResult[2]);
												}
											} else {
												if (regexResult[2] < dojo.date.getDaysInMonth(set[zz])) {
													newDate.setDate(regexResult[2]);
												}
											}
											subset.push(newDate);
										}
										tmp = set.concat(subset);
										set = tmp;
									}
								}
							}
						} else {
							dojo.debug("TODO: byday within a yearly rule without a bymonth");
						}
					}

					dojo.debug("TODO: Process BYrules for units larger than frequency");
			
					//add this set of events to the complete recurranceSet	
					var tmp = recurranceSet.concat(set);
					recurranceSet = tmp;
				}
			}

			// TODO: add rdates to the recurrance set here

			// TODO: subtract exdates from the recurrance set here

			//TODO:  subtract dates generated by exrules from recurranceSet here

			recurranceSet.push(dtstart);
			return recurranceSet;
		},

		getDate: function() {
			return dojo.date.fromIso8601(this.dtstart.value);
		}
});

/*
 * VTIMEZONE
 */

var VTimeZoneProperties = [
	_P("tzid", 1, true), _P("last-mod", 1), _P("tzurl", 1)

	// one of 'standardc' or 'daylightc' must occur
	// and each may occur more than once.
];

dojo.iCalendar.VTimeZone = function (/* string */ body) {
	// summary
	// VTIMEZONE Component
	this.name = "VTIMEZONE";
	this._ValidProperties = VTimeZoneProperties;
	dojo.iCalendar.Component.call(this, body);
}

dojo.inherits(dojo.iCalendar.VTimeZone, dojo.iCalendar.Component);

/*
 * VTODO
 */

var VTodoProperties = [
	// these can occur once only
	_P("class", 1), _P("completed", 1), _P("created", 1), _P("description", 1),
	_P("dtstart", 1), _P("geo", 1), _P("last-mod", 1), _P("location", 1),
	_P("organizer", 1), _P("percent", 1), _P("priority", 1), _P("dtstamp", 1),
	_P("seq", 1), _P("status", 1), _P("summary", 1), _P("uid", 1), _P("url", 1),
	_P("recurid", 1),
	// these two are exclusive
	[_P("due", 1), _P("duration", 1)],
	// these can occur many times over
	_P("attach"), _P("attendee"), _P("categories"), _P("comment"), _P("contact"),
	_P("exdate"), _P("exrule"), _P("rstatus"), _P("related"), _P("resources"),
	_P("rdate"), _P("rrule")
];

dojo.iCalendar.VTodo= function (/* string */ body) {
	// summary
	// VTODO Componenet
	this.name = "VTODO";
	this._ValidProperties = VTodoProperties;
	dojo.iCalendar.Component.call(this, body);
}

dojo.inherits(dojo.iCalendar.VTodo, dojo.iCalendar.Component);

/*
 * VJOURNAL
 */

var VJournalProperties = [
	// these can occur once only
	_P("class", 1), _P("created", 1), _P("description", 1), _P("dtstart", 1),
	_P("last-mod", 1), _P("organizer", 1), _P("dtstamp", 1), _P("seq", 1),
	_P("status", 1), _P("summary", 1), _P("uid", 1), _P("url", 1), _P("recurid", 1),
	// these can occur many times over
	_P("attach"), _P("attendee"), _P("categories"), _P("comment"), _P("contact"),
	_P("exdate"), _P("exrule"), _P("related"), _P("rstatus"), _P("rdate"), _P("rrule")
];

dojo.iCalendar.VJournal= function (/* string */ body) {
	// summary
	// VJOURNAL Component
	this.name = "VJOURNAL";
	this._ValidProperties = VJournalProperties;
	dojo.iCalendar.Component.call(this, body);
}

dojo.inherits(dojo.iCalendar.VJournal, dojo.iCalendar.Component);

/*
 * VFREEBUSY
 */

var VFreeBusyProperties = [
	// these can occur once only
	_P("contact"), _P("dtstart", 1), _P("dtend"), _P("duration"),
	_P("organizer", 1), _P("dtstamp", 1), _P("uid", 1), _P("url", 1),
	// these can occur many times over
	_P("attendee"), _P("comment"), _P("freebusy"), _P("rstatus")
];

dojo.iCalendar.VFreeBusy= function (/* string */ body) {
	// summary
	// VFREEBUSY Component
	this.name = "VFREEBUSY";
	this._ValidProperties = VFreeBusyProperties;
	dojo.iCalendar.Component.call(this, body);
}

dojo.inherits(dojo.iCalendar.VFreeBusy, dojo.iCalendar.Component);

/*
 * VALARM
 */

var VAlarmProperties = [
	[_P("action", 1, true), _P("trigger", 1, true), [_P("duration", 1), _P("repeat", 1)],
	_P("attach", 1)],

	[_P("action", 1, true), _P("description", 1, true), _P("trigger", 1, true),
	[_P("duration", 1), _P("repeat", 1)]],

	[_P("action", 1, true), _P("description", 1, true), _P("trigger", 1, true),
	_P("summary", 1, true), _P("attendee", "*", true),
	[_P("duration", 1), _P("repeat", 1)],
	_P("attach", 1)],

	[_P("action", 1, true), _P("attach", 1, true), _P("trigger", 1, true),
	[_P("duration", 1), _P("repeat", 1)],
	_P("description", 1)],
];

dojo.iCalendar.VAlarm= function (/* string */ body) {
	// summary
	// VALARM Component
	this.name = "VALARM";
	this._ValidProperties = VAlarmProperties;
	dojo.iCalendar.Component.call(this, body);
}

dojo.inherits(dojo.iCalendar.VAlarm, dojo.iCalendar.Component);

