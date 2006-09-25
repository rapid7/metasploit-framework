/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.widget.html.DocPane");

dojo.require("dojo.widget.*");
dojo.require("dojo.io.*");
dojo.require("dojo.event.*");
dojo.require("dojo.widget.HtmlWidget");

dojo.widget.html.DocPane = function(){
	dojo.widget.HtmlWidget.call(this);

	this.templatePath = dojo.uri.dojoUri("src/widget/templates/HtmlDocPane.html");
	this.templateCssPath = dojo.uri.dojoUri("src/widget/templates/HtmlDocPane.css");
	this.widgetType = "DocPane";
	this.isContainer = true;

	this.select;
	this.result;
	this.fn;
	this.fnLink;
	this.count;
	this.row;
	this.summary;
	this.description;
	this.variables;
	this.vRow;
	this.vLink;
	this.vDesc;
	this.parameters;
	this.pRow;
	this.pLink;
	this.pDesc;
	this.pOpt;
	this.pType;
	this.source;
	this.sType;
	this.sName;
	this.sParams;
	this.sPType;
	this.sPTypeSave;
	this.sPName;
	this.sPNameSave;

	dojo.event.topic.subscribe("/doc/results", this, "onDocResults");
	dojo.event.topic.subscribe("/doc/functionDetail", this, "onDocSelectFunction");
}

dojo.inherits(dojo.widget.html.DocPane, dojo.widget.HtmlWidget);

dojo.lang.extend(dojo.widget.html.DocPane, {
	fillInTemplate: function(){
		this.homeSave = this.containerNode.cloneNode(true);
		this.selectSave = dojo.dom.removeNode(this.select);
		this.resultSave = dojo.dom.removeNode(this.result);
		this.rowParent = this.row.parentNode;
		this.rowSave = dojo.dom.removeNode(this.row);
		this.vParent = this.vRow.parentNode;
		this.vSave = dojo.dom.removeNode(this.vRow);
		this.pParent = this.pRow.parentNode;
		this.pSave = dojo.dom.removeNode(this.pRow);
		this.sPTypeSave = dojo.dom.removeNode(this.sPType);
		this.sPNameSave = dojo.dom.removeNode(this.sPName);
	},

	onDocSelectFunction: function(message){
		var meta = message.meta;
		if(meta){
			var variables = meta.variables;
			var this_variables = meta.this_variables;
			var child_variables = meta.child_variables;
			var parameters = meta.parameters;
		}
		var doc = message.doc;

		var appends = [];
		dojo.dom.removeChildren(this.domNode);
		this.fn.innerHTML = message.name;
		this.description.innerHTML = doc.description;

		this.variables.style.display = "block";
		var all = [];
		if(variables){
			all = variables;
		}
		if(this_variables){
			all = all.concat(this_variables);
		}
		if(child_variables){
			all = all.concat(child_variables);
		}
		if(!all.length){
			this.variables.style.display = "none";
		}else{
			for(var i = 0, one; one = all[i]; i++){
				this.vLink.innerHTML = one;
				this.vDesc.parentNode.style.display = "none";
				appends.push(this.vParent.appendChild(this.vSave.cloneNode(true)));
			}
		}
		
		this.sParams.innerHTML = "";
		for(var param in parameters){
			var paramType = parameters[param][0];
			var paramName = parameters[param][1];
			this.parameters.style.display = "block";		
			this.pLink.innerHTML = paramName;
			this.pOpt.style.display = "none";
			if(parameters[param].opt){
				this.pOpt.style.display = "inline";				
			}
			this.pType.parentNode.style.display = "none";
			if(parameters[param][0]){
				this.pType.parentNode.style.display = "inline";
				this.pType.innerHTML = paramType;
			}
			this.pDesc.parentNode.style.display = "none";
			if(doc.parameters[paramName] && doc.parameters[paramName].description){
				this.pDesc.parentNode.style.display = "inline";
				this.pDesc.innerHTML = doc.parameters[paramName].description;
			}
			appends.push(this.pParent.appendChild(this.pSave.cloneNode(true)));
			
			if(param > 0) {
				this.sParams.appendChild(document.createTextNode(", "));
			}
			if(paramType){
				dojo.debug(this.sPTypeSave);
				this.sPTypeSave.innerHTML = paramType;
				this.sParams.appendChild(this.sPTypeSave.cloneNode(true));
				this.sParams.appendChild(document.createTextNode(" "));
			}
			dojo.debug(this.sPNameSave);
			this.sPNameSave.innerHTML = paramName;
			this.sParams.appendChild(this.sPNameSave.cloneNode(true))
		}

		if(message.returns){
			this.sType.innerHTML = message.returns;
		}else{
			this.sType.innerHTML = "void";
		}
		
		this.sName.innerHTML = message.name;
		
		dojo.dom.removeChildren(this.source);
                this.source.appendChild(document.createTextNode("\n\r"));
		this.source.appendChild(document.createTextNode(message.src.replace(/\n/g, "\r\n\t")));
                this.source.appendChild(document.createTextNode("\n\r"));
		
		this.domNode.appendChild(this.selectSave.cloneNode(true));

		for(var i = 0, append; append = appends[i]; i++){
			dojo.dom.removeNode(append);
		}
	},

	onDocResults: function(message){
		var results = message.docResults;
		
		if(results.length == 1){
			dojo.event.topic.publish("/doc/selectFunction", results[0]);
			return;
		}

		dojo.dom.removeChildren(this.domNode);

		this.count.innerHTML = results.length;
		var appends = [];
		for(var i = 0, row; row = results[i]; i++){
			this.fnLink.innerHTML = row.name;
			this.fnLink.href = "#" + row.name;
			if(row.id){
				this.fnLink.href = this.fnLink.href + "," + row.id;	
			}
			this.summary.parentNode.style.display = "none";
			if(row.summary){
				this.summary.parentNode.style.display = "inline";				
				this.summary.innerHTML = row.summary;
			}
			appends.push(this.rowParent.appendChild(this.rowSave.cloneNode(true)));
		}
		
		function makeSelect(x){
			return function(e) {
				dojo.event.topic.publish("/doc/selectFunction", x);
			}
		}

		this.domNode.appendChild(this.resultSave.cloneNode(true));
		var as = this.domNode.getElementsByTagName("a");
		for(var i = 0, a; a = as[i]; i++){
			dojo.event.connect(a, "onclick", makeSelect(results[i]));
		}
		
		for(var i = 0, append; append = appends[i]; i++){
			this.rowParent.removeChild(append);
		}
	}
});

dojo.widget.tags.addParseTreeHandler("dojo:DocPane");
