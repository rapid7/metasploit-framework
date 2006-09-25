/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.DropdownDatePicker");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.DropdownContainer");
dojo.require("dojo.widget.DatePicker");
dojo.require("dojo.event.*");
dojo.require("dojo.html");

dojo.widget.defineWidget(
	"dojo.widget.DropdownDatePicker",
	dojo.widget.DropdownContainer,
	{
		iconURL: dojo.uri.dojoUri("src/widget/templates/images/dateIcon.gif"),
		iconAlt: "Select a Date",
		zIndex: "10",
		datePicker: null,
		
		dateFormat: "%m/%d/%Y",
		date: null,
		
		fillInTemplate: function(args, frag){
			dojo.widget.DropdownDatePicker.superclass.fillInTemplate.call(this, args, frag);
			var source = this.getFragNodeRef(frag);
			
			if(args.date){ this.date = new Date(args.date); }
			
			var dpNode = document.createElement("div");
			this.containerNode.appendChild(dpNode);
			
			var dateProps = { widgetContainerId: this.widgetId };
			if(this.date){
				dateProps["date"] = this.date;
				dateProps["storedDate"] = dojo.widget.DatePicker.util.toRfcDate(this.date);
				this.inputNode.value = dojo.date.format(this.date, this.dateFormat);
			}
			this.datePicker = dojo.widget.createWidget("DatePicker", dateProps, dpNode);
			dojo.event.connect(this.datePicker, "onSetDate", this, "onSetDate");
			this.containerNode.style.zIndex = this.zIndex;
			this.containerNode.style.backgroundColor = "transparent";
		},
		
		onSetDate: function(){
			this.inputNode.value = dojo.date.format(this.datePicker.date, this.dateFormat);
			this.hideContainer();
		},
		
		onInputChange: function(){
			var tmp = new Date(this.inputNode.value);
			this.datePicker.date = tmp;
			this.datePicker.setDate(dojo.widget.DatePicker.util.toRfcDate(tmp));
			this.datePicker.initData();
			this.datePicker.initUI();
		}
	},
	"html"
);

dojo.widget.tags.addParseTreeHandler("dojo:dropdowndatepicker");
