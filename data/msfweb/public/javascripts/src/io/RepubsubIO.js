//	Copyright (c) 2004 Friendster Inc., Licensed under the Academic Free
//	License version 2.0 or later 

dojo.require("dojo.event.Event");
dojo.require("dojo.event.BrowserEvent");
dojo.require("dojo.io.BrowserIO");

dojo.provide("dojo.io.RepubsubIO");
dojo.provide("dojo.io.repubsub");
dojo.provide("dojo.io.repubsubTransport");

dojo.io.repubsubTranport = new function(){
	var rps = dojo.io.repubsub;
	this.canHandle = function(kwArgs){
		if((kwArgs["mimetype"] == "text/javascript")&&(kwArgs["method"] == "repubsub")){
			return true;
		}
		return false;
	}

	this.bind = function(kwArgs){
		if(!rps.isInitialized){
			// open up our tunnel, queue up requests anyway
			rps.init();
		}
		// FIXME: we need to turn this into a topic subscription
		// var tgtURL = kwArgs.url+"?"+dojo.io.argsFromMap(kwArgs.content);
		// sampleTransport.sendRequest(tgtURL, hdlrFunc);

		// a normal "bind()" call in a request-response transport layer is
		// something that (usually) encodes most of it's payload with the
		// request. Multi-event systems like repubsub are a bit more complex,
		// and repubsub in particular distinguishes the publish and subscribe
		// portions of thep rocess with different method calls to handle each.
		// Therefore, a "bind" in the sense of repubsub must first determine if
		// we have an open subscription to a channel provided by the server,
		// and then "publish" the request payload if there is any. We therefore
		// must take care not to incorrectly or too agressively register or
		// file event handlers which are provided with the kwArgs method.

		// NOTE: we ONLY pay attention to those event handlers that are
		// registered with the bind request that subscribes to the channel. If
		// event handlers are provided with subsequent requests, we might in
		// the future support some additive or replacement syntax, but for now
		// they get dropped on the floor.

		// NOTE: in this case, url MUST be the "topic" to which we
		// subscribe/publish for this channel
		if(!rps.topics[kwArgs.url]){
			kwArgs.rpsLoad = function(evt){
				kwArgs.load("load", evt);
			}
			rps.subscribe(kwArgs.url, kwArgs, "rpsLoad");
		}

		if(kwArgs["content"]){
			// what we wanted to send
			var cEvt = dojo.io.repubsubEvent.initFromProperties(kwArgs.content);
			rps.publish(kwArgs.url, cEvt);
		}
	}

	dojo.io.transports.addTransport("repubsubTranport");
}

dojo.io.repubsub = new function(){
	this.initDoc = "init.html";
	this.isInitialized = false;
	this.subscriptionBacklog = [];
	this.debug = true;
	this.rcvNodeName = null;
	this.sndNodeName = null;
	this.rcvNode = null;
	this.sndNode = null;
	this.canRcv = false;
	this.canSnd = false;
	this.canLog = false;
	this.sndTimer = null;
	this.windowRef = window;
	this.backlog = [];
	this.tunnelInitCount = 0;
	this.tunnelFrameKey = "tunnel_frame";
	this.serverBaseURL = location.protocol+"//"+location.host+location.pathname;
	this.logBacklog = [];
	this.getRandStr = function(){
		return Math.random().toString().substring(2, 10);
	}
	this.userid = "guest";
	this.tunnelID = this.getRandStr();
	this.attachPathList = [];
	this.topics = []; // list of topics we have listeners to

	// actually, now that I think about it a little bit more, it would sure be
	// useful to parse out the <script> src attributes. We're looking for
	// something with a "do_method=lib", since that's what would have included
	// us in the first place (in the common case).
	this.parseGetStr = function(){
		var baseUrl = document.location.toString();
		var params = baseUrl.split("?", 2);
		if(params.length > 1){
			var paramStr = params[1];
			var pairs = paramStr.split("&");
			var opts = [];
			for(var x in pairs){
				var sp = pairs[x].split("=");
				// FIXME: is this eval dangerous?
				try{
					opts[sp[0]]=eval(sp[1]);
				}catch(e){
					opts[sp[0]]=sp[1];
				}
			}
			return opts;
		}else{
			return [];
		}
	}

	// parse URL params and use them as default vals
	var getOpts = this.parseGetStr();
	for(var x in getOpts){
		// FIXME: should I be checking for undefined here before setting? Does
		//        that buy me anything?
		this[x] = getOpts[x];
	}

	if(!this["tunnelURI"]){
		this.tunnelURI = [	"/who/", escape(this.userid), "/s/", 
							this.getRandStr(), "/kn_journal"].join("");
		// this.tunnelURI = this.absoluteTopicURI(this.tunnelURI);
	}

	/*
	if (self.kn_tunnelID) kn.tunnelID = self.kn_tunnelID; // the server says
	if (kn._argv.kn_tunnelID) kn.tunnelID = kn._argv.kn_tunnelID; // the url says
	*/

	// check the options object if it exists and use its properties as an
	// over-ride
	if(window["repubsubOpts"]||window["rpsOpts"]){
		var optObj = window["repubsubOpts"]||window["rpsOpts"];
		for(var x in optObj){
			this[x] = optObj[x]; // copy the option object properties
		}
	}

	// things that get called directly from our iframe to inform us of events
	this.tunnelCloseCallback = function(){
		// when we get this callback, we should immediately attempt to re-start
		// our tunnel connection
		dojo.io.setIFrameSrc(this.rcvNode, this.initDoc+"?callback=repubsub.rcvNodeReady&domain="+document.domain);
	}

	this.receiveEventFromTunnel = function(evt, srcWindow){
		// we should never be getting events from windows we didn't create
		// NOTE: events sourced from the local window are also supported for
		// 		 debugging purposes

		// any event object MUST have a an "elements" property
		if(!evt["elements"]){
			this.log("bailing! event received without elements!", "error");
			return;
		}

		// if the event passes some minimal sanity tests, we need to attempt to
		// dispatch it!

		// first, it seems we have to munge the event object a bit
		var e = {};
		for(var i=0; i<evt.elements.length; i++){
			var ee = evt.elements[i];
			e[ee.name||ee.nameU] = (ee.value||ee.valueU);
			// FIXME: need to enable this only in some extreme debugging mode!
			this.log("[event]: "+(ee.name||ee.nameU)+": "+e[ee.name||ee.nameU]);
		}

		// NOTE: the previous version of this library put a bunch of code here
		// to manage state that tried to make sure that we never, ever, lost
		// any info about an event. If we unload RIGHT HERE, I don't think it's
		// going to make a huge difference one way or another. Time will tell.

		// and with THAT out of the way, dispatch it!
		this.dispatch(e);

		// TODO: remove the script block that created the event obj to save
		// memory, etc.
	}

	this.widenDomain = function(domainStr){
		// the purpose of this is to set the most liberal domain policy
		// available
		var cd = domainStr||document.domain;
		if(cd.indexOf(".")==-1){ return; } // probably file:/// or localhost
		var dps = cd.split(".");
		if(dps.length<=2){ return; } // probably file:/// or an RFC 1918 address
		dps = dps.slice(dps.length-2);
		document.domain = dps.join(".");
	}

	// FIXME: parseCookie and setCookie should be methods that are more broadly
	// available. Perhaps in htmlUtils?

	this.parseCookie = function(){
		var cs = document.cookie;
		var keypairs = cs.split(";");
		for(var x=0; x<keypairs.length; x++){
			keypairs[x] = keypairs[x].split("=");
			if(x!=keypairs.length-1){ cs+=";"; }
		}
		return keypairs;
	}

	this.setCookie = function(keypairs, clobber){
		// NOTE: we want to only ever set session cookies, so never provide an
		// 		 expires date
		if((clobber)&&(clobber==true)){ document.cookie = ""; }
		var cs = "";
		for(var x=0; x<keypairs.length; x++){
			cs += keypairs[x][0]+"="+keypairs[x][1];
			if(x!=keypairs.length-1){ cs+=";"; }
		}
		document.cookie = cs;
	}

	// FIXME: need to replace w/ dojo.log.*
	this.log = function(str, lvl){
		if(!this.debug){ return; } // we of course only care if we're in debug mode
		while(this.logBacklog.length>0){
			if(!this.canLog){ break; }
			var blo = this.logBacklog.shift();
			this.writeLog("["+blo[0]+"]: "+blo[1], blo[2]);
		}
		this.writeLog(str, lvl);
	}

	this.writeLog = function(str, lvl){
		dojo.debug(((new Date()).toLocaleTimeString())+": "+str);
	}

	this.init = function(){
		this.widenDomain();
		// this.findPeers();
		this.openTunnel();
		this.isInitialized = true;
		// FIXME: this seems like entirely the wrong place to replay the backlog
		while(this.subscriptionBacklog.length){
			this.subscribe.apply(this, this.subscriptionBacklog.shift());
		}
	}

	this.clobber = function(){
		if(this.rcvNode){
			this.setCookie( [
					[this.tunnelFrameKey,"closed"],
					["path","/"]
				], false 
			);
		}
	}

	this.openTunnel = function(){
		// We create two iframes here:

		// one for getting data
		this.rcvNodeName = "rcvIFrame_"+this.getRandStr();
		// set cookie that can be used to find the receiving iframe
		this.setCookie( [
				[this.tunnelFrameKey,this.rcvNodeName],
				["path","/"]
			], false
		);

		this.rcvNode = dojo.io.createIFrame(this.rcvNodeName);
		// FIXME: set the src attribute here to the initialization URL
		dojo.io.setIFrameSrc(this.rcvNode, this.initDoc+"?callback=repubsub.rcvNodeReady&domain="+document.domain);

		// the other for posting data in reply

		this.sndNodeName = "sndIFrame_"+this.getRandStr();
		this.sndNode = dojo.io.createIFrame(this.sndNodeName);
		// FIXME: set the src attribute here to the initialization URL
		dojo.io.setIFrameSrc(this.sndNode, this.initDoc+"?callback=repubsub.sndNodeReady&domain="+document.domain);

	}

	this.rcvNodeReady = function(){
		// FIXME: why is this sequence number needed? Why isn't the UID gen
		// 		  function enough?
        var statusURI = [this.tunnelURI, '/kn_status/', this.getRandStr(), '_', 
						 String(this.tunnelInitCount++)].join(""); 
            // (kn._seqNum++); // FIXME: !!!!
		// this.canRcv = true;
		this.log("rcvNodeReady");
		// FIXME: initialize receiver and request the base topic
		// dojo.io.setIFrameSrc(this.rcvNode, this.serverBaseURL+"/kn?do_method=blank");
		var initURIArr = [	this.serverBaseURL, "/kn?kn_from=", escape(this.tunnelURI),
							"&kn_id=", escape(this.tunnelID), "&kn_status_from=", 
							escape(statusURI)];
		// FIXME: does the above really need a kn_response_flush? won't the
		// 		  server already know? If not, what good is it anyway?
		dojo.io.setIFrameSrc(this.rcvNode, initURIArr.join(""));

		// setup a status path listener, but don't tell the server about it,
		// since it already knows we're itnerested in our own tunnel status
		this.subscribe(statusURI, this, "statusListener", true);

		this.log(initURIArr.join(""));
	}

	this.sndNodeReady = function(){
		this.canSnd = true;
		this.log("sndNodeReady");
		this.log(this.backlog.length);
		// FIXME: handle any pent-up send commands
		if(this.backlog.length > 0){
			this.dequeueEvent();
		}
	}

	this.statusListener = function(evt){
		this.log("status listener called");
		this.log(evt.status, "info");
	}

	// this handles local event propigation
	this.dispatch = function(evt){
		// figure out what topic it came from
		if(evt["to"]||evt["kn_routed_from"]){
			var rf = evt["to"]||evt["kn_routed_from"];
			// split off the base server URL
			var topic = rf.split(this.serverBaseURL, 2)[1];
			if(!topic){
				// FIXME: how do we recover when we don't get a sane "from"? Do
				// we try to route to it anyway?
				topic = rf;
			}
			this.log("[topic] "+topic);
			if(topic.length>3){
				if(topic.slice(0, 3)=="/kn"){
					topic = topic.slice(3);
				}
			}
			if(this.attachPathList[topic]){
				this.attachPathList[topic](evt);
			}
		}
	}

	this.subscribe = function(	topic /* kn_from in the old terminilogy */, 
								toObj, toFunc, dontTellServer){
		if(!this.isInitialized){
			this.subscriptionBacklog.push([topic, toObj, toFunc, dontTellServer]);
			return;
		}
		if(!this.attachPathList[topic]){
			this.attachPathList[topic] = function(){ return true; }
			this.log("subscribing to: "+topic);
			this.topics.push(topic);
		}
		var revt = new dojo.io.repubsubEvent(this.tunnelURI, topic, "route");
		var rstr = [this.serverBaseURL+"/kn", revt.toGetString()].join("");
		dojo.event.kwConnect({
			once: true,
			srcObj: this.attachPathList, 
			srcFunc: topic, 
			adviceObj: toObj, 
			adviceFunc: toFunc
		});
		// NOTE: the above is a local mapping, if we're not the leader, we
		// 		 should connect our mapping to the topic handler of the peer
		// 		 leader, this ensures that not matter what happens to the
		// 		 leader, we don't really loose our heads if/when the leader
		// 		 goes away.
		if(!this.rcvNode){ /* this should be an error! */ }
		if(dontTellServer){
			return;
		}
		this.log("sending subscription to: "+topic);
		// create a subscription event object and give it all the props we need
		// to updates on the specified topic

		// FIXME: we should only enqueue if this is our first subscription!
		this.sendTopicSubToServer(topic, rstr);
	}

	this.sendTopicSubToServer = function(topic, str){
		if(!this.attachPathList[topic]["subscriptions"]){
			this.enqueueEventStr(str);
			this.attachPathList[topic].subscriptions = 0;
		}
		this.attachPathList[topic].subscriptions++;
	}

	this.unSubscribe = function(topic, toObj, toFunc){
		// first, locally disconnect
		dojo.event.kwDisconnect({
			srcObj: this.attachPathList, 
			srcFunc: topic, 
			adviceObj: toObj, 
			adviceFunc: toFunc
		});
		
		// FIXME: figure out if there are any remaining listeners to the topic,
		// 		  and if not, inform the server of our desire not to be
		// 		  notified of updates to the topic
	}

	// the "publish" method is really a misnomer, since it really means "take
	// this event and send it to the server". Note that the "dispatch" method
	// handles local event promigulation, and therefore we emulate both sides
	// of a real event router without having to swallow all of the complexity.
	this.publish = function(topic, event){
		var evt = dojo.io.repubsubEvent.initFromProperties(event);
		// FIXME: need to make sure we have from and to set correctly
		// 		  before we serialize and send off to the great blue
		// 		  younder.
		evt.to = topic;
		// evt.from = this.tunnelURI;

		var evtURLParts = [];
		evtURLParts.push(this.serverBaseURL+"/kn");

		// serialize the event to a string and then post it to the correct
		// topic
		evtURLParts.push(evt.toGetString());
		this.enqueueEventStr(evtURLParts.join(""));
	}

	this.enqueueEventStr = function(evtStr){
		this.log("enqueueEventStr");
		this.backlog.push(evtStr);
		this.dequeueEvent();
	}

	this.dequeueEvent = function(force){
		this.log("dequeueEvent");
		if(this.backlog.length <= 0){ return; }
		if((this.canSnd)||(force)){
			dojo.io.setIFrameSrc(this.sndNode, this.backlog.shift()+"&callback=repubsub.sndNodeReady");
			this.canSnd = false;
		}else{
			this.log("sndNode not available yet!", "debug");
		}
	}
}

dojo.io.repubsubEvent = function(to, from, method, id, routeURI, payload, dispname, uid){
	this.to = to;
	this.from = from;
	this.method = method||"route";
	this.id = id||repubsub.getRandStr();
	this.uri = routeURI;
	this.displayname = dispname||repubsub.displayname;
	this.userid = uid||repubsub.userid;
	this.payload = payload||"";
	this.flushChars = 4096;

	this.initFromProperties = function(evt){
		if(evt.constructor = dojo.io.repubsubEvent){ 
			for(var x in evt){
				this[x] = evt[x];
			}
		}else{
			// we want to copy all the properties of the evt object, and transform
			// those that are "stock" properties of dojo.io.repubsubEvent. All others should
			// be copied as-is
			for(var x in evt){
				if(typeof this.forwardPropertiesMap[x] == "string"){
					this[this.forwardPropertiesMap[x]] = evt[x];
				}else{
					this[x] = evt[x];
				}
			}
		}
	}

	this.toGetString = function(noQmark){
		var qs = [ ((noQmark) ? "" : "?") ];
		for(var x=0; x<this.properties.length; x++){
			var tp = this.properties[x];
			if(this[tp[0]]){
				qs.push(tp[1]+"="+encodeURIComponent(String(this[tp[0]])));
			}
			// FIXME: we need to be able to serialize non-stock properties!!!
		}
		return qs.join("&");
	}

}

dojo.io.repubsubEvent.prototype.properties = [["from", "kn_from"], ["to", "kn_to"], 
									["method", "do_method"], ["id", "kn_id"], 
									["uri", "kn_uri"], 
									["displayname", "kn_displayname"], 
									["userid", "kn_userid"], 
									["payload", "kn_payload"],
									["flushChars", "kn_response_flush"],
									["responseFormat", "kn_response_format"] ];

// maps properties from their old names to their new names...
dojo.io.repubsubEvent.prototype.forwardPropertiesMap = {};
// ...and vice versa...
dojo.io.repubsubEvent.prototype.reversePropertiesMap = {};

// and we then populate them both from the properties list
for(var x=0; x<dojo.io.repubsubEvent.prototype.properties.length; x++){
	var tp = dojo.io.repubsubEvent.prototype.properties[x];
	dojo.io.repubsubEvent.prototype.reversePropertiesMap[tp[0]] = tp[1];
	dojo.io.repubsubEvent.prototype.forwardPropertiesMap[tp[1]] = tp[0];
}
// static version of initFromProperties, creates new event and object and
// returns it after init
dojo.io.repubsubEvent.initFromProperties = function(evt){
	var eventObj = new dojo.io.repubsubEvent();
	eventObj.initFromProperties(evt);
	return eventObj;
}
