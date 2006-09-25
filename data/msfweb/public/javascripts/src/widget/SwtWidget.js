/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.SwtWidget");

dojo.require("dojo.event.*");
dojo.require("dojo.widget.Widget");
dojo.require("dojo.uri.*");
dojo.require("dojo.lang.func");
dojo.require("dojo.lang.extras");

try{
	importPackage(Packages.org.eclipse.swt.widgets);

	dojo.declare("dojo.widget.SwtWidget", dojo.widget.Widget, {
		initializer: function() {
			if((arguments.length>0)&&(typeof arguments[0] == "object")){
				this.create(arguments[0]);
			}
		},

		display: null,
		shell: null,

		show: function(){ },
		hide: function(){ },

		addChild: function(){ },
		registerChild: function(){ },
		addWidgetAsDirectChild: function(){ },
		removeChild: function(){ },
		cleanUp: function(){ },
		destroyRendering: function(){ },
		postInitialize: function(){ },
	});

	// initialize SWT runtime

	dojo.widget.SwtWidget.prototype.display = new Display();
	dojo.widget.SwtWidget.prototype.shell = new Shell(dojo.widget.SwtWidget.prototype.display);

	dojo.widget.manager.startShell = function(){
		var sh = dojo.widget.SwtWidget.prototype.shell;
		var d = dojo.widget.SwtWidget.prototype.display;
		sh.open();
		while(!sh.isDisposed()){
			dojo.widget.manager.doNext();
			if(!d.readAndDispatch()){
				d.sleep();
			}
		}
		d.dispose();
	};
}catch(e){
	// seems we didn't have the SWT classes in the environment. Log it.
	dojo.debug("dojo.widget.SwtWidget not loaded. SWT classes not available");
}
