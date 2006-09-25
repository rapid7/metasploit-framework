/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.io.ShortBusIO");
dojo.require("dojo.io"); // io.js provides setIFrameSrc
// FIXME: determine if we can use XMLHTTP to make x-domain posts despite not
//        being able to hear back about the result
dojo.require("dojo.io.IframeIO"); // for posting across domains
dojo.require("dojo.io.cookie"); // for peering
dojo.require("dojo.event.*");

/*
 * this file defines a "forever-frame" style Comet client. It passes opaque
 * JSON data structures to/from the client. Both styles of request provide a
 * topic for the event to be sent to and a payload object to be acted upon.
 *
 * All outbound events are sent via dojo.io.bind() and all inbound requests are
 * processed by Dojo topic dispatch.
 *
 * ShortBusIO packets have the basic format:
 *
 *	{
 *	 	topic: "/destination/topic/name",
 *		body: {
 * 			// ...
 *		}
 * 	}
 * 
 * Packets bound for the event router (not one of it's clients) or generated
 * from it are prefixed with the special "/meta" topic. Meta-topic events
 * either inform the client to take an action or inform the server of a system
 * event.
 *
 * Upon tunnel creation, the server might therefore send the following meta
 * topic packet to the client to inform the client of it's assigned identity:
 *
 *	// client <-- server
 *	{
 *	 	topic: "/meta",
 *		body: {
 * 			action: "setClientId",
 *			clientId: "fooBar23",
 *			tunnelId: "fooBarTunnel4",
 *			tunnelExpiration: "...", // some date in the future
 *		}
 * 	}
 *
 * The client may then respond with a confirmation:
 * 
 *	// client --> server
 *	{
 *	 	topic: "/meta",
 *		body: {
 * 			action: "confirmClientId",
 *			from: "fooBar23"
 *		}
 * 	}
 *
 * The client must implement a basic vocabulary of /meta topic verbs in order
 * to participate as a ShortBus endpoint. These are TBD.
 *
 * NOTE: this example elides any authentication or authorization steps the
 * client and server may have undertaken prior to tunnel setup.
 */

// TODO: unlike repubsubio we don't handle any sort of connection
// subscription/publishing backlog. Should we?

dojo.io.ShortBusTransport = new function(){

	var initialized = false;
	var connected = false;

	// this class is similar to RepubsubIO save that we don't have the
	// externalized protocol handler code. Our messages are simpler so our code
	// can be as well.

	this.rcvNode = null;
	this.rcvNodeName = "";
	this.topicRoot = null;

	this.getRandStr = function(){
		return Math.random().toString().substring(2, 10);
	}

	this.widenDomain = function(domainStr){
		// allow us to make reqests to the TLD
		var cd = domainStr||document.domain;
		if(cd.indexOf(".")==-1){ return; } // probably file:/// or localhost
		var dps = cd.split(".");
		if(dps.length<=2){ return; } // probably file:/// or an RFC 1918 address
		dps = dps.slice(dps.length-2);
		document.domain = dps.join(".");
	}

	this.canHandle = function(kwArgs){
		return (
			(connected)			&&
			(kwArgs["topic"])	&&
			(! // async only!
				((kwArgs["sync"])&&(kwArgs["sync"] == true))
			)
		);
	}

	this.buildConnection = function(){
		// NOTE: we require the server to cooperate by hosting
		// ShortBusInit.html at the designated endpoint
		this.rcvNodeName = "ShortBusRcv_"+this.getRandStr();
		// the "forever frame" approach
		if(dojo.render.html.ie){
			// use the "htmlfile hack" to prevent the background click junk
			this.rcvNode = new ActiveXObject("htmlfile");
			this.rcvNode.open();
			this.rcvNode.write("<html>");
			this.rcvNode.write("<script>document.domain = '"+document.domain+"'");
			this.rcvNode.write("</html>");
			this.rcvNode.close();

			var ifrDiv = this.rcvNode.createElement("div");
			this.rcvNode.appendChild(ifrDiv);
			this.rcvNode.parentWindow.dojo = dojo;
			ifrDiv.innerHTML = "<iframe src='"+this.topicRoot+"/?tunntelType=htmlfile'></iframe>"
			// and we're ready to go!
			connected = true;
		}else{
			this.rcvNode = dojo.io.createIFrame(this.rcvNodeName);
			dojo.io.setIFrameSrc(this.rcvNode, this.topicRoot+"/?tunnelType=iframe");
			// we're still waiting on this one to call back up and advertise
			// that it's been initialized
		}
	}

	this.iframeConnectionInit = function(){
		connected = true;
	}

	this.dispatchServerEvent = function(eObj){
		// FIXME: implement basic /meta topic semantics here!
	}

	this.init = function(){
		if(initialized){
			return;
		}
		initialized = true;

		this.widenDomain();

		// we want to set up a connection to the designated server. Grab the
		// server location out of djConfig.
		this.topicRoot = djConfig["ShortBusRoot"];
		if(!this.topicRoot){
			dojo.debug("no topic root specified in djConfig.ShortBusRoot");
			return;
		}
	}

	this.dispatch = function(evt){
		// dipatch events along the specified path
	}

    dojo.io.transports.addTransport("ShortBusTransport");
}
