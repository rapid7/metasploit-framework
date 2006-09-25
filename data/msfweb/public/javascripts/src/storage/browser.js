/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.storage.browser");
dojo.provide("dojo.storage.browser.FlashStorageProvider");

dojo.require("dojo.storage");
dojo.require("dojo.flash");
dojo.require("dojo.json");
dojo.require("dojo.uri.*");

/** 
		Storage provider that uses features in Flash to achieve permanent storage.
		
		@author Alex Russel, alex@dojotoolkit.org
		@author Brad Neuberg, bkn3@columbia.edu 
*/
dojo.storage.browser.FlashStorageProvider = function(){
}

dojo.inherits(dojo.storage.browser.FlashStorageProvider, dojo.storage);

// instance methods and properties
dojo.lang.extend(dojo.storage.browser.FlashStorageProvider, {
	namespace: "default",
	initialized: false,
	_available: null,
	_statusHandler: null,
	
	initialize: function(){
		if(djConfig["disableFlashStorage"] == true){
			return;
		}
		
		// initialize our Flash
		var loadedListener = function(){
			dojo.storage._flashLoaded();
		}
		dojo.flash.addLoadedListener(loadedListener);
		var swfloc6 = dojo.uri.dojoUri("Storage_version6.swf").toString();
		var swfloc8 = dojo.uri.dojoUri("Storage_version8.swf").toString();
		dojo.flash.setSwf({flash6: swfloc6, flash8: swfloc8, visible: false});
	},
	
	isAvailable: function(){
		if(djConfig["disableFlashStorage"] == true){
			this._available = false;
		}
		
		return this._available;
	},
	
	setNamespace: function(namespace){
		this.namespace = namespace;
	},

	put: function(key, value, resultsHandler){
		if(this.isValidKey(key) == false){
			dojo.raise("Invalid key given: " + key);
		}
			
		this._statusHandler = resultsHandler;
		
		// serialize the value
		// Handle strings differently so they have better performance
		if(dojo.lang.isString(value)){
			value = "string:" + value;
		}else{
			value = dojo.json.serialize(value);
		}
		
		dojo.flash.comm.put(key, value, this.namespace);
	},

	get: function(key){
		if(this.isValidKey(key) == false){
			dojo.raise("Invalid key given: " + key);
		}
		
		var results = dojo.flash.comm.get(key, this.namespace);

		if(results == ""){
			return null;
		}
    
		// destringify the content back into a 
		// real JavaScript object
		// Handle strings differently so they have better performance
		if(!dojo.lang.isUndefined(results) && results != null 
			 && /^string:/.test(results)){
			results = results.substring("string:".length);
		}else{
			results = dojo.json.evalJson(results);
		}
    
		return results;
	},

	getKeys: function(){
		var results = dojo.flash.comm.getKeys(this.namespace);
		
		if(results == ""){
			return new Array();
		}

		// the results are returned comma seperated; split them
		results = results.split(",");
		
		return results;
	},

	clear: function(){
		dojo.flash.comm.clear(this.namespace);
	},
	
	remove: function(key){
	},
	
	isPermanent: function(){
		return true;
	},

	getMaximumSize: function(){
		return dojo.storage.SIZE_NO_LIMIT;
	},

	hasSettingsUI: function(){
		return true;
	},

	showSettingsUI: function(){
		dojo.flash.comm.showSettings();
		dojo.flash.obj.setVisible(true);
		dojo.flash.obj.center();
	},

	hideSettingsUI: function(){
		// hide the dialog
		dojo.flash.obj.setVisible(false);
		
		// call anyone who wants to know the dialog is
		// now hidden
		if(dojo.storage.onHideSettingsUI != null &&
			!dojo.lang.isUndefined(dojo.storage.onHideSettingsUI)){
			dojo.storage.onHideSettingsUI.call(null);	
		}
	},
	
	/** 
			The provider name as a string, such as 
			"dojo.storage.FlashStorageProvider". 
	*/
	getType: function(){
		return "dojo.storage.FlashStorageProvider";
	},
	
	/** Called when the Flash is finished loading. */
	_flashLoaded: function(){
		this.initialized = true;

		// indicate that this storage provider is now loaded
		dojo.storage.manager.loaded();
	},
	
	/** 
			Called if the storage system needs to tell us about the status
			of a put() request. 
	*/
	_onStatus: function(statusResult, key){
		//dojo.debug("_onStatus, statusResult="+statusResult+", key="+key);
		if(statusResult == dojo.storage.PENDING){
			dojo.flash.obj.center();
			dojo.flash.obj.setVisible(true);
		}else{
			dojo.flash.obj.setVisible(false);
		}
		
		if(!dojo.lang.isUndefined(dojo.storage._statusHandler) 
				&& dojo.storage._statusHandler != null){
			dojo.storage._statusHandler.call(null, statusResult, key);		
		}
	}
});

// register the existence of our storage providers
dojo.storage.manager.register("dojo.storage.browser.FlashStorageProvider",
                              new dojo.storage.browser.FlashStorageProvider());

// now that we are loaded and registered tell the storage manager to initialize
// itself
dojo.storage.manager.initialize();
															
