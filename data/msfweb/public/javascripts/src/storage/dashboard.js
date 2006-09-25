/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.require("dojo.storage");
dojo.require("dojo.json");
dojo.provide("dojo.storage.dashboard");

dojo.storage.dashboard.StorageProvider = function(){
	this.initialized = false;
}

dojo.inherits(dojo.storage.dashboard.StorageProvider, dojo.storage.StorageProvider);

dojo.lang.extend(dojo.storage.dashboard.StorageProvider, {
	storageOnLoad: function(){
		this.initialized = true;
	},

	set: function(key, value, ns){
		if (ns && widget.system){
			widget.system("/bin/mkdir " + ns);
			var system = widget.system("/bin/echo " + value + " >" + ns + "/" + key);
			if(system.errorString){
				return false;
			}
			return true;
		}

		return widget.setPreferenceForKey(dojo.json.serialize(value), key);
	},

	get: function(key, ns){
		if (ns && widget.system) {
			var system = widget.system("/bin/cat " + ns + "/" + key);
			if(system.errorString){
				return "";
			}
			return system.outputString;
		}

		return dojo.json.evalJson(widget.preferenceForKey(key));
	}
});

dojo.storage.setProvider(new dojo.storage.dashboard.StorageProvider());
