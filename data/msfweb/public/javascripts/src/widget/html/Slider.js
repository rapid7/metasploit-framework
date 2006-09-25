/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/**
 * Slider Widget.
 * 
 * The slider widget comes in three forms:
 *  1. Base Slider widget which supports movement in x and y dimensions
 *  2. Vertical Slider (SliderVertical) widget which supports movement
 *     only in the y dimension.
 *  3. Horizontal Slider (SliderHorizontal) widget which supports movement
 *     only in the x dimension.
 *
 * The key objects in the widget are:
 *  - a container div which displays a bar in the background (Slider object)
 *  - a handle inside the container div, which represents the value
 *    (sliderHandle DOM node)
 *  - the object which moves the handle (handleMove is of type 
 *    SliderDragMoveSource)
 *
 * The values for the slider are calculated by grouping pixels together, 
 * based on the number of values to be represented by the slider.
 * The number of pixels in a group is called the valueSize
 *  e.g. if slider is 150 pixels long, and is representing the values
 *       0,1,...10 then pixels are grouped into lots of 15 (valueSize), where:
 *         value 0 maps to pixels  0 -  7
 *               1                 8 - 22
 *               2                23 - 37 etc.
 * The accuracy of the slider is limited to the number of pixels
 * (i.e tiles > pixels will result in the slider not being able to
 *  represent some values).
 *
 * Technical Notes:
 *  - 3 widgets exist because the framework caches the template in
 *    dojo.widget.fillFromTemplateCache (which ignores the changed URI)
 *
 * Todo:
 *  - Setting of initial value currently doesn't work, because the one or
 *    more of the offsets, constraints or containing block are not set and
 *    are required to set the valueSize is not set before fillInTemplate
 *    is called.
 *  - Issues with dragging handle when page has been scrolled
 *  - 
 *
 * References (aka sources of inspiration):
 *  - http://dojotoolkit.org/docs/fast_widget_authoring.html
 *  - http://dojotoolkit.org/docs/dojo_event_system.html
 * 
 * @author Marcel Linnenfelser (m.linnen@synflag.de)
 * @author Mathew Pole (mathew.pole@ebor.com)
 *
 * $Id: $
 */

// tell the package system what functionality is provided in this module (file)
// (note that the package system works on modules, not the classes)
dojo.provide("dojo.widget.html.Slider");

// load dependencies
dojo.require("dojo.event.*");
dojo.require("dojo.dnd.*");
// dojo.dnd.* doesn't include this package, because it's not in __package__.js
dojo.require("dojo.dnd.HtmlDragMove");
dojo.require("dojo.widget.*");
dojo.require("dojo.style");


/**
 * Define the two dimensional slider widget class.
 */
dojo.widget.defineWidget (
	"dojo.widget.html.Slider",
	dojo.widget.HtmlWidget,
	{
		// over-ride some defaults
		isContainer: false,
		widgetType: "Slider",

		// useful properties (specified as attributes in the html tag)
		// number of values to be represented by slider in the horizontal direction
		valuesX: 10,
		// number of values to be represented by slider in the vertical direction
		valuesY: 10,
		// can values be changed on the x (horizontal) axis?
		isEnableX: true,
		// can values be changed on the y (vertical) axis?
		isEnableY: true,
		// value size (pixels) in the x dimension
		valueSizeX: 0.0,
		// value size (pixels) in the y dimension
		valueSizeY: 0.0,
		// initial value in the x dimension
		initialValueX: 0,
		// initial value in the y dimension
		initialValueY: 0,

		// do we allow the user to click on the slider to set the position?
		// (note: dojo's infrastructor will convert attribute to a boolean)
		clickSelect: true,
		// should the handle snap to the grid or remain where it was dragged to?
		// (note: dojo's infrastructor will convert attribute to a boolean)
		snapToGrid: false,
		// should the value change while you are dragging, or just after drag finishes?
		activeDrag: false,

		templateCssPath: dojo.uri.dojoUri ("src/widget/templates/HtmlSlider.css"),
		templatePath: dojo.uri.dojoUri ("src/widget/templates/HtmlSlider.html"),

		// our DOM nodes
		sliderHandle: null,

		// private attributes
		// This is set to true when a drag is started, so that it is not confused
		// with a click
		isDragInProgress: false,


		// This function is called when the template is loaded
		fillInTemplate: function () 
		{
			// dojo.debug ("fillInTemplate - className = " + this.domNode.className);

			// setup drag-n-drop for the sliderHandle
			this.handleMove = new dojo.widget.html.SliderDragMoveSource (this.sliderHandle);
			this.handleMove.setParent (this);
			dojo.event.connect(this.handleMove, "onDragMove", this, "onDragMove");
			dojo.event.connect(this.handleMove, "onDragEnd", this, "onDragEnd");
			dojo.event.connect(this.handleMove, "onClick", this, "onClick");

			// keep the slider handle inside it's parent container
			this.handleMove.constrainToContainer = true;
		
			if (this.clickSelect) {
				dojo.event.connect (this.domNode, "onclick", this, "setPosition");
			} 

			if (this.isEnableX && this.initialValueX > 0) {
				alert("setting x to " + this.initialValueX);
				this.setValueX (this.initialValueX);
			}
			if (this.isEnableY && this.initialValueY > 0) {
				this.setValueY (this.initialValueY);
			}
		},


		// Move the handle (in the x dimension) to the specified value
		setValueX: function (value) {
			if (0.0 == this.valueSizeX) {
				this.valueSizeX = this.handleMove.calcValueSizeX ();
			}
			if (value > this.valuesX) {
				value = this.valuesX;
			}
			else if (value < 0) {
				value = 0;
			}
			//dojo.debug ("value = " + value, ", valueSizeX = " + this.valueSizeX);
			this.handleMove.domNode.style.left = (value * this.valueSizeX) + "px";
		},


		// Get the number of the value that matches the position of the handle
		getValueX: function () {
			if (0.0 == this.valueSizeX) {
				this.valueSizeX = this.handleMove.calcValueSizeX ();
			}
			return Math.round (dojo.style.getPixelValue (this.handleMove.domNode, "left") / this.valueSizeX);
		},


		// set the slider to a particular value
		setValueY: function (value) {
			if (0.0 == this.valueSizeY) {
				this.valueSizeY = this.handleMove.calcValueSizeY ();
			}
			if (value > this.valuesY) {
				value = this.valuesY;
			}
			else if (value < 0) {
				value = 0;
			}

			this.handleMove.domNode.style.top = (value * this.valueSizeY) + "px";
		},


		// Get the number of the value that the matches the position of the handle
		getValueY: function () {
			if (0.0 == this.valueSizeY) {
				this.valueSizeY = this.handleMove.calcValueSizeY ();
			}
			return Math.round (dojo.style.getPixelValue (this.handleMove.domNode, "top") / this.valueSizeY);
		},


		// set the position of the handle
		setPosition: function (e) {
			//dojo.debug ("Slider#setPosition - e.clientX = " + e.clientX
			//            + ", e.clientY = " + e.clientY);
			if (this.isDragInProgress) {
				this.isDragInProgress = false;
			}

			var offset = dojo.html.getScrollOffset();
			var parent = dojo.style.getAbsolutePosition(this.domNode, true);
			
			if (this.isEnableX) {
				var x = offset.x + e.clientX - parent.x;
				if (x > this.domNode.offsetWidth) {
					x = this.domNode.offsetWidth;
				}
				if (this.snapToGrid && x > 0) {
					if (0.0 == this.valueSizeX) {
						this.valueSizeX = this.handleMove.calcValueSizeX ();
					}
					x = this.valueSizeX * (Math.round (x / this.valueSizeX));
				}
				this.handleMove.domNode.style.left = x + "px";
			}
			if (this.isEnableY) {
				var y = offset.y + e.clientY - parent.y;
				if (y > this.domNode.offsetHeight) {
					y = this.domNode.offsetHeight;
				}
				if (this.snapToGrid && y > 0) {
					if (0.0 == this.valueSizeY) {
						this.valueSizeY = this.handleMove.calcValueSizeY ();
					}
					y = this.valueSizeY * (Math.round (y / this.valueSizeY));
				}
				this.handleMove.domNode.style.top = y + "px";
			}
		},

		onDragMove: function(){
			this.onValueChanged(this.getValueX(), this.getValueY());
		},
	
		onClick: function(){
			this.onValueChanged(this.getValueX(), this.getValueY());
		},
		
		onValueChanged: function(x, y){
		}
	}
);


/* ------------------------------------------------------------------------- */


/**
 * Define the horizontal slider widget class.
 */
dojo.widget.defineWidget (
	"dojo.widget.html.SliderHorizontal",
	dojo.widget.html.Slider,
	{
		widgetType: "SliderHorizontal",

		value: 0,

		isEnableY: false,
		templatePath: dojo.uri.dojoUri ("src/widget/templates/HtmlSliderHorizontal.html"),

		postMixInProperties: function(){
			this.initialValue = this.value;
		},

		// wrapper for getValueX
		getValue: function () {
			return this.getValueX ();
		},

		// wrapper for setValueX
		setValue: function (value) {
			this.setValueX (value);
			this.onValueChanged(value);
		},

		onDragMove: function(){
			if(this.activeDrag){
				this.onValueChanged(this.getValue());
			}
		},
	
		onDragEnd: function(){
			if(!this.activeDrag){
				this.onValueChanged(this.getValue());
			}
		},
	
		onClick: function(){
			this.onValueChanged(this.getValue());
		},
		
		onValueChanged: function(value){
			this.value=value;
		}
	}
);


/* ------------------------------------------------------------------------- */


/**
 * Define the vertical slider widget class.
 */
dojo.widget.defineWidget (
	"dojo.widget.html.SliderVertical",
	dojo.widget.html.Slider,
	{
		widgetType: "SliderVertical",

		value: 0,

		isEnableX: false,
		templatePath: dojo.uri.dojoUri ("src/widget/templates/HtmlSliderVertical.html"),

		postMixInProperties: function(){
			this.initialValueY = this.value;
		},

		// wrapper for getValueY
		getValue: function () {
			return this.getValueY ();
		},

		// wrapper for setValueY
		setValue: function (value) {
			this.setValueY (value);
		},

		onDragMove: function(){
			if(this.activeDrag){
				this.onValueChanged(this.getValue());
			}
		},
	
		onDragEnd: function(){
			if(!this.activeDrag){
				this.onValueChanged(this.getValue());
			}
		},
	
		onClick: function(){
			this.onValueChanged(this.getValue());
		},
		
		onValueChanged: function(value){
			this.value=value;
		}
	}
);


/* ------------------------------------------------------------------------- */


/**
 * This class extends the HtmlDragMoveSource class to provide
 * features for the slider handle.
 */
dojo.declare (
	"dojo.widget.html.SliderDragMoveSource",
	dojo.dnd.HtmlDragMoveSource,
{
	isDragInProgress: false,
	slider: null,


	/** Setup the handle for drag
	 *  Extends dojo.dnd.HtmlDragMoveSource by creating a SliderDragMoveSource */
	onDragStart: function (e) {
		this.isDragInProgress = true;
		this.constrainToContainer = true;

		var dragObj = this.createDragMoveObject ();
		var constraints = null;


		dojo.event.connect (dragObj, "onDragMove", this, "onDragMove");

		return dragObj;
	},


	onDragMove: function (e) {
		// placeholder to enable event connection
	},


	createDragMoveObject: function () {
		//dojo.debug ("SliderDragMoveSource#createDragMoveObject - " + this.slider);
		var dragObj = new dojo.widget.html.SliderDragMoveObject (this.dragObject, this.type);
		dragObj.slider = this.slider;

		// this code copied from dojo.dnd.HtmlDragSource#onDragStart
		if (this.dragClass) { 
			dragObj.dragClass = this.dragClass; 
		}
		if (this.constrainToContainer) {
			dragObj.constrainTo(this.constrainingContainer || this.domNode.parentNode);
		}
		return dragObj;
	},


	setParent: function (slider) {
		this.slider = slider;
	},

	
	calcValueSizeX: function () {
		var dragObj = this.createDragMoveObject ();
		dragObj.containingBlockPosition = dragObj.domNode.offsetParent ? 
		dojo.style.getAbsolutePosition(dragObj.domNode.offsetParent) : {x:0, y:0};
		
		var constraints = dragObj.getConstraints ();
		return (constraints.maxX - constraints.minX) / this.slider.valuesX;
	},

	
	calcValueSizeY: function () {
		var dragObj = this.createDragMoveObject ();
		dragObj.containingBlockPosition = dragObj.domNode.offsetParent ? 
		dojo.style.getAbsolutePosition(dragObj.domNode.offsetParent) : {x:0, y:0};
		var constraints = dragObj.getConstraints ();
		return (constraints.maxY - constraints.minY) / this.slider.valuesY;
	}
});


/* ------------------------------------------------------------------------- */


/**
 * This class extends the HtmlDragMoveObject class to provide
 * features for the slider handle.
 */
dojo.declare (
	"dojo.widget.html.SliderDragMoveObject",
	dojo.dnd.HtmlDragMoveObject,
{
	// reference to dojo.widget.html.Slider
	slider: null,

	/** Moves the node to follow the mouse.
	 *  Extends functon HtmlDragObject by adding functionality to snap handle
	 *  to a discrete value */
	onDragMove: function (e) {
		if (this.slider.isEnableX && 0.0 == this.slider.valueSizeX) {
			this.slider.valueSizeX = (this.constraints.maxX - this.constraints.minX) / this.slider.valuesX;
		}
		if (this.slider.isEnableY && 0.0 == this.slider.valueSizeY) {
			this.slider.valueSizeY = (this.constraints.maxY - this.constraints.minY) / this.slider.valuesY;
		}

		this.updateDragOffset ();

		var x = this.dragOffset.x + e.pageX;
		var y = this.dragOffset.y + e.pageY;

		if (this.constrainToContainer) {
			if (x < this.constraints.minX) { x = this.constraints.minX; }
			if (y < this.constraints.minY) { y = this.constraints.minY; }
			if (x > this.constraints.maxX) { x = this.constraints.maxX; }
			if (y > this.constraints.maxY) { y = this.constraints.maxY; }
		}

		if (this.slider.isEnableX) {
			var selectedValue = 0;
			if (x > 0) {
				selectedValue = Math.round (x / this.slider.valueSizeX);
			}
			// dojo.debug ("x = " + x + ", valueSize = " + valueSize 
			//             + ", selectedValue = " + selectedValue);
			x = (selectedValue * this.slider.valueSizeX);
		}

		if (this.slider.isEnableY) {
			var selectedValue = 0;
			if (y > 0) {
				selectedValue = Math.round (y / this.slider.valueSizeY);
			}
			y = (selectedValue * this.slider.valueSizeY);
		}

		this.setAbsolutePosition (x, y);
	}
});
