/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Select");
dojo.provide("dojo.widget.html.Select");

dojo.require("dojo.widget.html.ComboBox");
dojo.require("dojo.widget.*");
dojo.require("dojo.widget.html.stabile");

/*
 * The Select widget is an enhanced version of HTML's <select> tag.
 *
 * Similar features:
 *   - There is a drop down list of possible values.
 *   - You can only enter a value from the drop down list.  (You can't enter an arbitrary value.)
 *   - The value submitted with the form is the hidden value (ex: CA),
       not the displayed value a.k.a. label (ex: California)
 *
 * Enhancements over plain HTML version:
 *   - If you type in some text then it will filter down the list of possible values in the drop down list.
 *   - List can be specified either as a static list or via a javascript function (that can get the list from a server)
 */

dojo.widget.defineWidget(
	"dojo.widget.html.Select",
	dojo.widget.html.ComboBox,
	{
		widgetType: "Select",
		forceValidOption: true,

		setValue: function(value) {
			this.comboBoxValue.value = value;
			dojo.widget.html.stabile.setState(this.widgetId, this.getState(), true);
		},

		setLabel: function(value){
			// FIXME, not sure what to do here!
			this.comboBoxSelectionValue.value = value;
			if (this.textInputNode.value != value) { // prevent mucking up of selection
				this.textInputNode.value = value;
			}
		},	  

		getLabel: function(){
			return this.comboBoxSelectionValue.value;
		},

		getState: function() {
			return {
				value: this.getValue(),
				label: this.getLabel()
			};
		},

		onKeyUp: function(evt){
			this.setLabel(this.textInputNode.value);
		},

		setState: function(state) {
			this.setValue(state.value);
			this.setLabel(state.label);
		},

		setAllValues: function(value1, value2){
			this.setValue(value2);
			this.setLabel(value1);
		}
	});
