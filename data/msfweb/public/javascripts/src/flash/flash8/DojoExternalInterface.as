/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/**
	A wrapper around Flash 8's ExternalInterface; DojoExternalInterface is needed so that we
	can do a Flash 6 implementation of ExternalInterface, and be able
	to support having a single codebase that uses DojoExternalInterface
	across Flash versions rather than having two seperate source bases,
	where one uses ExternalInterface and the other uses DojoExternalInterface.
	
	DojoExternalInterface class does a variety of optimizations to bypass ExternalInterface's
	unbelievably bad performance so that we can have good performance
	on Safari; see the blog post
	http://codinginparadise.org/weblog/2006/02/how-to-speed-up-flash-8s.html
	for details.
	
	@author Brad Neuberg, bkn3@columbia.edu
*/
import flash.external.ExternalInterface;

class DojoExternalInterface{
	public static var available:Boolean;
	public static var dojoPath = "";
	
	private static var flashMethods:Array = new Array();
	private static var numArgs:Number;
	private static var argData:Array;
	private static var resultData = null;
	
	public static function initialize(){
		// extract the dojo base path
		DojoExternalInterface.dojoPath = DojoExternalInterface.getDojoPath();
		
		// see if we need to do an express install
		var install:ExpressInstall = new ExpressInstall();
		if(install.needsUpdate){
			install.init();
		}
		
		// register our callback functions
		ExternalInterface.addCallback("startExec", DojoExternalInterface, startExec);
		ExternalInterface.addCallback("setNumberArguments", DojoExternalInterface,
																	setNumberArguments);
		ExternalInterface.addCallback("chunkArgumentData", DojoExternalInterface,
																	chunkArgumentData);
		ExternalInterface.addCallback("exec", DojoExternalInterface, exec);
		ExternalInterface.addCallback("getReturnLength", DojoExternalInterface,
																	getReturnLength);
		ExternalInterface.addCallback("chunkReturnData", DojoExternalInterface,
																	chunkReturnData);
		ExternalInterface.addCallback("endExec", DojoExternalInterface, endExec);
		
		// set whether communication is available
		DojoExternalInterface.available = ExternalInterface.available;
		DojoExternalInterface.call("loaded");
	}
	
	public static function addCallback(methodName:String, instance:Object, 
										 								 method:Function) : Boolean{
		// register DojoExternalInterface methodName with it's instance
		DojoExternalInterface.flashMethods[methodName] = instance;
		
		// tell JavaScript about DojoExternalInterface new method so we can create a proxy
		ExternalInterface.call("dojo.flash.comm._addExternalInterfaceCallback", 
													 methodName);
													 
		return true;
	}
	
	public static function call(methodName:String,
								resultsCallback:Function) : Void{
		// we might have any number of optional arguments, so we have to 
		// pass them in dynamically; strip out the results callback
		var parameters = new Array();
		for(var i = 0; i < arguments.length; i++){
			if(i != 1){ // skip the callback
				parameters.push(arguments[i]);
			}
		}
		
		var results = ExternalInterface.call.apply(ExternalInterface, parameters);
		
		// immediately give the results back, since ExternalInterface is
		// synchronous
		if(resultsCallback != null && typeof resultsCallback != "undefined"){
			resultsCallback.call(null, results);
		}
	}
	
	/** 
			Called by Flash to indicate to JavaScript that we are ready to have
			our Flash functions called. Calling loaded()
			will fire the dojo.flash.loaded() event, so that JavaScript can know that
			Flash has finished loading and adding its callbacks, and can begin to
			interact with the Flash file.
	*/
	public static function loaded(){
		DojoExternalInterface.call("dojo.flash.loaded");
	}
	
	public static function startExec():Void{
		DojoExternalInterface.numArgs = null;
		DojoExternalInterface.argData = null;
		DojoExternalInterface.resultData = null;
	}
	
	public static function setNumberArguments(numArgs):Void{
		DojoExternalInterface.numArgs = numArgs;
		DojoExternalInterface.argData = new Array(DojoExternalInterface.numArgs);
	}
	
	public static function chunkArgumentData(value, argIndex:Number):Void{
		//getURL("javascript:dojo.debug('FLASH: chunkArgumentData, value="+value+", argIndex="+argIndex+"')");
		var currentValue = DojoExternalInterface.argData[argIndex];
		if(currentValue == null || typeof currentValue == "undefined"){
			DojoExternalInterface.argData[argIndex] = value;
		}else{
			DojoExternalInterface.argData[argIndex] += value;
		}
	}
	
	public static function exec(methodName):Void{
		// decode all of the arguments that were passed in
		for(var i = 0; i < DojoExternalInterface.argData.length; i++){
			DojoExternalInterface.argData[i] = 
				DojoExternalInterface.decodeData(DojoExternalInterface.argData[i]);
		}
		
		var instance = DojoExternalInterface.flashMethods[methodName];
		DojoExternalInterface.resultData = instance[methodName].apply(
																			instance, DojoExternalInterface.argData);
		// encode the result data
		DojoExternalInterface.resultData = 
			DojoExternalInterface.encodeData(DojoExternalInterface.resultData);
			
		//getURL("javascript:dojo.debug('FLASH: encoded result data="+DojoExternalInterface.resultData+"')");
	}
	
	public static function getReturnLength():Number{
	 if(DojoExternalInterface.resultData == null || 
	 					typeof DojoExternalInterface.resultData == "undefined"){
	 	return 0;
	 }
	 var segments = Math.ceil(DojoExternalInterface.resultData.length / 1024);
	 return segments;
	}
	
	public static function chunkReturnData(segment:Number):String{
		var numSegments = DojoExternalInterface.getReturnLength();
		var startCut = segment * 1024;
		var endCut = segment * 1024 + 1024;
		if(segment == (numSegments - 1)){
			endCut = segment * 1024 + DojoExternalInterface.resultData.length;
		}
			
		var piece = DojoExternalInterface.resultData.substring(startCut, endCut);
		
		//getURL("javascript:dojo.debug('FLASH: chunking return piece="+piece+"')");
		
		return piece;
	}
	
	public static function endExec():Void{
	}
	
	private static function decodeData(data):String{
		// we have to use custom encodings for certain characters when passing
		// them over; for example, passing a backslash over as //// from JavaScript
		// to Flash doesn't work
		data = DojoExternalInterface.replaceStr(data, "&custom_backslash;", "\\");
		
		data = DojoExternalInterface.replaceStr(data, "\\\'", "\'");
		data = DojoExternalInterface.replaceStr(data, "\\\"", "\"");
		
		return data;
	}
	
	private static function encodeData(data){
		//getURL("javascript:dojo.debug('inside flash, data before="+data+"')");

		// double encode all entity values, or they will be mis-decoded
		// by Flash when returned
		data = DojoExternalInterface.replaceStr(data, "&", "&amp;");
		
		// certain XMLish characters break Flash's wire serialization for
		// ExternalInterface; encode these into a custom encoding, rather than
		// the standard entity encoding, because otherwise we won't be able to
		// differentiate between our own encoding and any entity characters
		// that are being used in the string itself
		data = DojoExternalInterface.replaceStr(data, '<', '&custom_lt;');
		data = DojoExternalInterface.replaceStr(data, '>', '&custom_gt;');
		
		// encode control characters and JavaScript delimiters
		data = DojoExternalInterface.replaceStr(data, "\n", "\\n");
		data = DojoExternalInterface.replaceStr(data, "\r", "\\r");
		data = DojoExternalInterface.replaceStr(data, "\f", "\\f");
		data = DojoExternalInterface.replaceStr(data, "'", "\\'");
		data = DojoExternalInterface.replaceStr(data, '"', '\"');
		
		//getURL("javascript:dojo.debug('inside flash, data after="+data+"')");
		return data;
	}
	
	/** 
			Flash ActionScript has no String.replace method or support for
			Regular Expressions! We roll our own very simple one.
	*/
	private static function replaceStr(inputStr:String, replaceThis:String, 
																		 withThis:String):String {
		var splitStr = inputStr.split(replaceThis)
		inputStr = splitStr.join(withThis)
		return inputStr;
	}
	
	private static function getDojoPath(){
		var url = _root._url;
		var start = url.indexOf("baseRelativePath=") + "baseRelativePath=".length;
		var path = url.substring(start);
		var end = path.indexOf("&");
		if(end != -1){
			path = path.substring(0, end);
		}
		return path;
	}
}

// vim:ts=4:noet:tw=0:
