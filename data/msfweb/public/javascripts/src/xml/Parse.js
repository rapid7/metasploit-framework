/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.xml.Parse");

dojo.require("dojo.dom");

//TODO: determine dependencies
// currently has dependency on dojo.xml.DomUtil nodeTypes constants...

/* generic method for taking a node and parsing it into an object

TODO: WARNING: This comment is wrong!

For example, the following xml fragment

<foo bar="bar">
	<baz xyzzy="xyzzy"/>
</foo>

can be described as:

dojo.???.foo = {}
dojo.???.foo.bar = {}
dojo.???.foo.bar.value = "bar";
dojo.???.foo.baz = {}
dojo.???.foo.baz.xyzzy = {}
dojo.???.foo.baz.xyzzy.value = "xyzzy"

*/
// using documentFragment nomenclature to generalize in case we don't want to require passing a collection of nodes with a single parent
dojo.xml.Parse = function(){

	function getDojoTagName (node) {
		var tagName = node.tagName;
		if (tagName.substr(0,5).toLowerCase() != "dojo:") {
			
			if (tagName.substr(0,4).toLowerCase() == "dojo") {
				// FIXME: this assuumes tag names are always lower case
				return "dojo:" + tagName.substring(4).toLowerCase();
			}
		
			// allow lower-casing
			var djt = node.getAttribute("dojoType") || node.getAttribute("dojotype");
			if (djt) { return "dojo:" + djt.toLowerCase(); }
			
			if (node.getAttributeNS && node.getAttributeNS(dojo.dom.dojoml,"type")) {
				return "dojo:" + node.getAttributeNS(dojo.dom.dojoml,"type").toLowerCase();
			}
			try {
				// FIXME: IE really really doesn't like this, so we squelch
				// errors for it
				djt = node.getAttribute("dojo:type");
			} catch (e) { /* FIXME: log? */ }

			if (djt) { return "dojo:"+djt.toLowerCase(); }
		
			if (!dj_global["djConfig"] || !djConfig["ignoreClassNames"]) {
				// FIXME: should we make this optionally enabled via djConfig?
				var classes = node.className||node.getAttribute("class");
				// FIXME: following line, without check for existence of classes.indexOf
				// breaks firefox 1.5's svg widgets
				if (classes && classes.indexOf && classes.indexOf("dojo-") != -1) {
					var aclasses = classes.split(" ");
					for(var x=0; x<aclasses.length; x++){
						if (aclasses[x].length > 5 && aclasses[x].indexOf("dojo-") >= 0) {
							return "dojo:"+aclasses[x].substr(5).toLowerCase();
						}
					}
				}
			}
		
		}
		return tagName.toLowerCase();
	}

	this.parseElement = function(node, hasParentNodeSet, optimizeForDojoML, thisIdx){

        // if parseWidgets="false" don't search inside this node for widgets
        if (node.getAttribute("parseWidgets") == "false") {
            return {};
        }

		// TODO: make this namespace aware
		var parsedNodeSet = {};

		var tagName = getDojoTagName(node);
		parsedNodeSet[tagName] = [];
		if((!optimizeForDojoML)||(tagName.substr(0,4).toLowerCase()=="dojo")){
			var attributeSet = parseAttributes(node);
			for(var attr in attributeSet){
				if((!parsedNodeSet[tagName][attr])||(typeof parsedNodeSet[tagName][attr] != "array")){
					parsedNodeSet[tagName][attr] = [];
				}
				parsedNodeSet[tagName][attr].push(attributeSet[attr]);
			}
	
			// FIXME: we might want to make this optional or provide cloning instead of
			// referencing, but for now, we include a node reference to allow
			// instantiated components to figure out their "roots"
			parsedNodeSet[tagName].nodeRef = node;
			parsedNodeSet.tagName = tagName;
			parsedNodeSet.index = thisIdx||0;
		}
	
		var count = 0;
		var tcn, i = 0, nodes = node.childNodes;
		while(tcn = nodes[i++]){
			switch(tcn.nodeType){
				case  dojo.dom.ELEMENT_NODE: // element nodes, call this function recursively
					count++;
					var ctn = getDojoTagName(tcn);
					if(!parsedNodeSet[ctn]){
						parsedNodeSet[ctn] = [];
					}
					parsedNodeSet[ctn].push(this.parseElement(tcn, true, optimizeForDojoML, count));
					if(	(tcn.childNodes.length == 1)&&
						(tcn.childNodes.item(0).nodeType == dojo.dom.TEXT_NODE)){
						parsedNodeSet[ctn][parsedNodeSet[ctn].length-1].value = tcn.childNodes.item(0).nodeValue;
					}
					break;
				case  dojo.dom.TEXT_NODE: // if a single text node is the child, treat it as an attribute
					if(node.childNodes.length == 1) {
						parsedNodeSet[tagName].push({ value: node.childNodes.item(0).nodeValue });
					}
					break;
				default: break;
				/*
				case  dojo.dom.ATTRIBUTE_NODE: // attribute node... not meaningful here
					break;
				case  dojo.dom.CDATA_SECTION_NODE: // cdata section... not sure if this would ever be meaningful... might be...
					break;
				case  dojo.dom.ENTITY_REFERENCE_NODE: // entity reference node... not meaningful here
					break;
				case  dojo.dom.ENTITY_NODE: // entity node... not sure if this would ever be meaningful
					break;
				case  dojo.dom.PROCESSING_INSTRUCTION_NODE: // processing instruction node... not meaningful here
					break;
				case  dojo.dom.COMMENT_NODE: // comment node... not not sure if this would ever be meaningful 
					break;
				case  dojo.dom.DOCUMENT_NODE: // document node... not sure if this would ever be meaningful
					break;
				case  dojo.dom.DOCUMENT_TYPE_NODE: // document type node... not meaningful here
					break;
				case  dojo.dom.DOCUMENT_FRAGMENT_NODE: // document fragment node... not meaningful here
					break;
				case  dojo.dom.NOTATION_NODE:// notation node... not meaningful here
					break;
				*/
			}
		}
		//return (hasParentNodeSet) ? parsedNodeSet[node.tagName] : parsedNodeSet;
		return parsedNodeSet;
	}

	/* parses a set of attributes on a node into an object tree */
	function parseAttributes(node) {
		// TODO: make this namespace aware
		var parsedAttributeSet = {};
		var atts = node.attributes;
		// TODO: should we allow for duplicate attributes at this point...
		// would any of the relevant dom implementations even allow this?
		var attnode, i=0;
		while(attnode=atts[i++]) {
			if((dojo.render.html.capable)&&(dojo.render.html.ie)){
				if(!attnode){ continue; }
				if(	(typeof attnode == "object")&&
					(typeof attnode.nodeValue == 'undefined')||
					(attnode.nodeValue == null)||
					(attnode.nodeValue == '')){ 
					continue; 
				}
			}
			var nn = (attnode.nodeName.indexOf("dojo:") == -1) ? attnode.nodeName : attnode.nodeName.split("dojo:")[1];
			parsedAttributeSet[nn] = { 
				value: attnode.nodeValue 
			};
		}
		return parsedAttributeSet;
	}
}
