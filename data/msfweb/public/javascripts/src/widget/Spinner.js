/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Spinner");
dojo.provide("dojo.widget.AdjustableIntegerTextbox");

dojo.require("dojo.widget.validate.IntegerTextbox");
dojo.require("dojo.widget.*");
dojo.require("dojo.event.*");

/*
  ****** AdjustableIntegerTextbox ******

  A subclass of IntegerTextbox.
*/
dojo.widget.AdjustableIntegerTextbox = function(node) {
        // this property isn't a primitive and needs to be created on a per-item basis.
        this.flags = {};
}
dojo.inherits(dojo.widget.AdjustableIntegerTextbox, dojo.widget.validate.IntegerTextbox);
dojo.lang.extend(dojo.widget.AdjustableIntegerTextbox, {
        // new subclass properties
        widgetType: "AdjustableIntegerTextbox",
		delta: "1",

        adjustValue: function(direction, x){
			var val = this.getValue().replace(/[^\-+\d]/g, "");
			if(val.length == 0){ return; }

			num = Math.min(Math.max((parseInt(val)+(parseInt(this.delta) * direction)), this.flags.min), this.flags.max);
			val = (new Number(num)).toString();

			if(num >= 0){
				val = ((this.flags.signed == true)?'+':' ')+val; // make sure first char is a nondigit
			}

			if(this.flags.separator.length > 0){
				for (var i=val.length-3; i > 1; i-=3){
					val = val.substr(0,i)+this.flags.separator+val.substr(i);
				}
			}

			if(val.substr(0,1) == ' '){ val = val.substr(1); } // remove space

			this.setValue(val);

			return val.length;
	}
});
dojo.widget.tags.addParseTreeHandler("dojo:AdjustableIntegerTextbox");

/*
  ****** AdjustableRealNumberTextbox ******

  A subclass of RealNumberTextbox.
  @attr places    The exact number of decimal places.  If omitted, it's unlimited and optional.
  @attr exponent  Can be true or false.  If omitted the exponential part is optional.
  @attr eSigned   Is the exponent signed?  Can be true or false, if omitted the sign is optional.
*/
dojo.widget.AdjustableRealNumberTextbox = function(node) {
        // this property isn't a primitive and needs to be created on a per-item basis.
        this.flags = {};
}
dojo.inherits(dojo.widget.AdjustableRealNumberTextbox, dojo.widget.validate.RealNumberTextbox);
dojo.lang.extend(dojo.widget.AdjustableRealNumberTextbox, {
        // new subclass properties
        widgetType: "AdjustableRealNumberTextbox",
		delta: "1e1",

        adjustValue: function(direction, x){
			var val = this.getValue().replace(/[^\-+\.eE\d]/g, "");
			if(!val.length){ return; }

			var num = parseFloat(val);
			if(isNaN(num)){ return; }
			var delta = this.delta.split(/[eE]/);
			if(!delta.length){
				delta = [1, 1];
			}else{
				delta[0] = parseFloat(delta[0].replace(/[^\-+\.\d]/g, ""));
				if(isNaN(delta[0])){ delta[0] = 1; }
				if(delta.length > 1){
					delta[1] = parseInt(delta[1]);
				}
				if(isNaN(delta[1])){ delta[1] = 1; }
			}
			val = this.getValue().split(/[eE]/);
			if(!val.length){ return; }
			var numBase = parseFloat(val[0].replace(/[^\-+\.\d]/g, ""));
			if(val.length == 1){
				var numExp = 0;
			}else{
				var numExp = parseInt(val[1].replace(/[^\-+\d]/g, ""));
			}
			if(x <= val[0].length){
				x = 0;
				numBase += delta[0] * direction;
			}else{
				x = Number.MAX_VALUE;
				numExp += delta[1] * direction;
				if(this.flags.eSigned == false && numExp < 0){
					numExp = 0;
				}
			}
			num = Math.min(Math.max((numBase * Math.pow(10,numExp)), this.flags.min), this.flags.max);
			if((this.flags.exponent == true || (this.flags.exponent != false && x != 0)) && num.toExponential){
				if (isNaN(this.flags.places) || this.flags.places == Infinity){
					val = num.toExponential();
				}else{
					val = num.toExponential(this.flags.places);
				}
			}else if(num.toFixed && num.toPrecision){
				if(isNaN(this.flags.places)){
					val = num.toPrecision((1/3).toString().length-1);
				}else{
					val = num.toFixed(this.flags.places);
				}
			}else{
				val = num.toString();
			}

			if(num >= 0){
				if(this.flags.signed == true){
					val = '+' + val;
				}
			}
			val = val.split(/[eE]/);
			if(this.flags.separator.length > 0){
				if(num >= 0 && val[0].substr(0,1) != '+'){
					val[0] = ' ' + val[0]; // make sure first char is nondigit for easy algorithm
				}
				var i = val[0].lastIndexOf('.');
				if(i >= 0){
					i -= 3;
				}else{
					i = val[0].length-3;
				}
				for (; i > 1; i-=3){
					val[0] = val[0].substr(0,i)+this.flags.separator+val[0].substr(i);
				}
				if(val[0].substr(0,1) == ' '){ val[0] = val[0].substr(1); } // remove space
			}
			if(val.length > 1){
				if((this.flags.eSigned == true)&&(val[1].substr(0,1) != '+')){
					val[1] = '+' + val[1];
				}else if((!this.flags.eSigned)&&(val[1].substr(0,1) == '+')){
					val[1] = val[1].substr(1);
				}else if((!this.flags.eSigned)&&(val[1].substr(0,1) == '-')&&(num.toFixed && num.toPrecision)){
					if(isNaN(this.flags.places)){
						val[0] = num.toPrecision((1/3).toString().length-1);
					}else{
						val[0] = num.toFixed(this.flags.places).toString();
					}
					val[1] = "0";
				}
				val[0] += 'e' + val[1];
			}
			this.setValue(val[0]);
			if(x > val[0].length){ x = val[0].length; }
			return x;
	}
});
dojo.widget.tags.addParseTreeHandler("dojo:AdjustableRealNumberTextbox");

dojo.widget.Spinner = function(){
	dojo.widget.Widget.call(this);
}

dojo.inherits(dojo.widget.Spinner, dojo.widget.Widget);

dojo.widget.Spinner.defaults = {
	widgetType: "Spinner",
	isContainer: false
};

dojo.lang.extend(dojo.widget.Spinner, dojo.widget.Spinner.defaults);

dojo.widget.DomSpinner = function(){
	dojo.widget.Spinner.call(this);
	dojo.widget.DomWidget.call(this, true);
}

dojo.inherits(dojo.widget.DomSpinner, dojo.widget.DomWidget);
dojo.widget.tags.addParseTreeHandler("dojo:Spinner");

// render-specific includes
dojo.requireAfterIf("html", "dojo.widget.html.Spinner");
