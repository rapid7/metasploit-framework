/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.AdapterRegistry");
dojo.require("dojo.lang.func");

dojo.AdapterRegistry = function(){
    /***
        A registry to facilitate adaptation.

        Pairs is an array of [name, check, wrap] triples
        
        All check/wrap functions in this registry should be of the same arity.
    ***/
    this.pairs = [];
}

dojo.lang.extend(dojo.AdapterRegistry, {
    register: function (name, check, wrap, /* optional */ override){
        /***
			The check function should return true if the given arguments are
			appropriate for the wrap function.

			If override is given and true, the check function will be given
			highest priority.  Otherwise, it will be the lowest priority
			adapter.
        ***/

        if (override) {
            this.pairs.unshift([name, check, wrap]);
        } else {
            this.pairs.push([name, check, wrap]);
        }
    },

    match: function (/* ... */) {
        /***
			Find an adapter for the given arguments.

			If no suitable adapter is found, throws NotFound.
        ***/
        for(var i = 0; i < this.pairs.length; i++){
            var pair = this.pairs[i];
            if(pair[1].apply(this, arguments)){
                return pair[2].apply(this, arguments);
            }
        }
		throw new Error("No match found");
        // dojo.raise("No match found");
    },

    unregister: function (name) {
        /***
			Remove a named adapter from the registry
        ***/
        for(var i = 0; i < this.pairs.length; i++){
            var pair = this.pairs[i];
            if(pair[0] == name){
                this.pairs.splice(i, 1);
                return true;
            }
        }
        return false;
    }
});
