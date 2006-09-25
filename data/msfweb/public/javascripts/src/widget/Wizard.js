/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.Wizard");

dojo.require("dojo.widget.*");
dojo.require("dojo.widget.LayoutContainer");
dojo.require("dojo.widget.ContentPane");
dojo.require("dojo.event.*");
dojo.require("dojo.html");
dojo.require("dojo.style");

//////////////////////////////////////////
// WizardContainer -- a set of panels
//////////////////////////////////////////
dojo.widget.WizardContainer = function() {
	dojo.widget.html.LayoutContainer.call(this);
}
dojo.inherits(dojo.widget.WizardContainer, dojo.widget.html.LayoutContainer);

dojo.lang.extend(dojo.widget.WizardContainer, {

	widgetType: "WizardContainer",

	labelPosition: "top",

	templatePath: dojo.uri.dojoUri("src/widget/templates/Wizard.html"),
	templateCssPath: dojo.uri.dojoUri("src/widget/templates/Wizard.css"),

	selected: null,		// currently selected panel
	wizardNode: null, // the outer wizard node
	wizardPanelContainerNode: null, // the container for the panels
	wizardControlContainerNode: null, // the container for the wizard controls
	previousButton: null, // the previous button
	nextButton: null, // the next button
	cancelButton: null, // the cancel button
	doneButton: null, // the done button
	nextButtonLabel: "next",
	previousButtonLabel: "previous",
	cancelButtonLabel: "cancel",
	doneButtonLabel: "done",
	cancelFunction : "",

	hideDisabledButtons: false,

	fillInTemplate: function(args, frag){
		dojo.event.connect(this.nextButton, "onclick", this, "nextPanel");
		dojo.event.connect(this.previousButton, "onclick", this, "previousPanel");
		if (this.cancelFunction){
			dojo.event.connect(this.cancelButton, "onclick", this.cancelFunction);
		}else{
			this.cancelButton.style.display = "none";
		}
		dojo.event.connect(this.doneButton, "onclick", this, "done");
		this.nextButton.value = this.nextButtonLabel;
		this.previousButton.value = this.previousButtonLabel;
		this.cancelButton.value = this.cancelButtonLabel;
		this.doneButton.value = this.doneButtonLabel;
	},

	checkButtons: function(){
		var lastStep = !this.hasNextPanel();
		this.nextButton.disabled = lastStep;
		this.setButtonClass(this.nextButton);
		if(this.selected.doneFunction){
			this.doneButton.style.display = "";
			// hide the next button if this is the last one and we have a done function
			if(lastStep){
				this.nextButton.style.display = "none";
			}
		}else{
			this.doneButton.style.display = "none";
		}
		this.previousButton.disabled = ((!this.hasPreviousPanel()) || (!this.selected.canGoBack));
		this.setButtonClass(this.previousButton);
	},

	setButtonClass: function(button){
		if(!this.hideDisabledButtons){
			button.style.display = "";
			dojo.html.setClass(button, button.disabled ? "WizardButtonDisabled" : "WizardButton");
		}else{
			button.style.display = button.disabled ? "none" : "";
		}
	},

	registerChild: function(panel, insertionIndex){
		dojo.widget.WizardContainer.superclass.registerChild.call(this, panel, insertionIndex);
		this.wizardPanelContainerNode.appendChild(panel.domNode);
		panel.hide();

		if(!this.selected){
			this.onSelected(panel);
		}
		this.checkButtons();
	},

	onSelected: function(panel){
		// Deselect old panel and select new one
		if(this.selected ){
			if (this.selected.checkPass()) {
				this.selected.hide();
			} else {
				return;
			}
		}
		panel.show();
		this.selected = panel;
	},

	getPanels: function() {
		return this.getChildrenOfType("WizardPane", false);
	},

	selectedIndex: function() {
		if (this.selected) {
			return dojo.lang.indexOf(this.getPanels(), this.selected);
		}
		return -1;
	},

	nextPanel: function() {
		var selectedIndex = this.selectedIndex();
		if ( selectedIndex > -1 ) {
			var childPanels = this.getPanels();
			if (childPanels[selectedIndex + 1]) {
				this.onSelected(childPanels[selectedIndex + 1]);
			}
		}
		this.checkButtons();
	},

	previousPanel: function() {
		var selectedIndex = this.selectedIndex();
		if ( selectedIndex > -1 ) {
			var childPanels = this.getPanels();
			if (childPanels[selectedIndex - 1]) {
				this.onSelected(childPanels[selectedIndex - 1]);
			}
		}
		this.checkButtons();
	},

	hasNextPanel: function() {
		var selectedIndex = this.selectedIndex();
		return (selectedIndex < (this.getPanels().length - 1));
	},

	hasPreviousPanel: function() {
		var selectedIndex = this.selectedIndex();
		return (selectedIndex > 0);
	},

	done: function() {
		this.selected.done();
	}
});
dojo.widget.tags.addParseTreeHandler("dojo:WizardContainer");

//////////////////////////////////////////
// WizardPane -- a panel in a wizard
//////////////////////////////////////////
dojo.widget.WizardPane = function() {
	dojo.widget.html.ContentPane.call(this);
}
dojo.inherits(dojo.widget.WizardPane, dojo.widget.html.ContentPane);

dojo.lang.extend(dojo.widget.WizardPane, {
	widgetType: "WizardPane",

	canGoBack: true,

	passFunction: "",
	doneFunction: "",

	fillInTemplate: function(args, frag) {
		if (this.passFunction) {
			this.passFunction = dj_global[this.passFunction];
		}
		if (this.doneFunction) {
			this.doneFunction = dj_global[this.doneFunction];
		}
	},

	checkPass: function() {
		if (this.passFunction && dojo.lang.isFunction(this.passFunction)) {
			var failMessage = this.passFunction();
			if (failMessage) {
				alert(failMessage);
				return false;
			}
		}
		return true;
	},

	done: function() {
		if (this.doneFunction && dojo.lang.isFunction(this.doneFunction)) {
			this.doneFunction();
		}
	}
});

dojo.widget.tags.addParseTreeHandler("dojo:WizardPane");
