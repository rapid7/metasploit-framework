/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

dojo.provide("dojo.profile");

dojo.profile = new function(){
	var profiles = {};
	var pns = [];

	this.start = function(name){
		if(!profiles[name]){
			profiles[name] = {iters: 0, total: 0};
			pns[pns.length] = name;
		}else{
			if(profiles[name]["start"]){
				this.end(name);
			}
		}
		profiles[name].end = null;
		profiles[name].start = new Date();
	}

	this.end = function(name){
		var ed = new Date();
		if((profiles[name])&&(profiles[name]["start"])){
			with(profiles[name]){
				end = ed;
				total += (end - start);
				start = null;
				iters++;
			}
		}else{
			// oops! bad call to end(), what should we do here?
			return true;
		}
	}

	this.stop = this.end;

	this.dump = function(appendToDoc){
		var tbl = document.createElement("table");
		with(tbl.style){
			border = "1px solid black";
			borderCollapse = "collapse";
		}
		var hdr = tbl.createTHead();
		var hdrtr = hdr.insertRow(0);
		// document.createElement("tr");
		var cols = ["Identifier","Calls","Total","Avg"];
		for(var x=0; x<cols.length; x++){
			var ntd = hdrtr.insertCell(x);
			with(ntd.style){
				backgroundColor = "#225d94";
				color = "white";
				borderBottom = "1px solid black";
				borderRight = "1px solid black";
				fontFamily = "tahoma";
				fontWeight = "bolder";
				paddingLeft = paddingRight = "5px";
			}
			ntd.appendChild(document.createTextNode(cols[x]));
		}

		for(var x=0; x < pns.length; x++){
			var prf = profiles[pns[x]];
			this.end(pns[x]);
			if(prf.iters>0){
				var bdytr = tbl.insertRow(true);
				var vals = [pns[x], prf.iters, prf.total, parseInt(prf.total/prf.iters)];
				for(var y=0; y<vals.length; y++){
					var cc = bdytr.insertCell(y);
					cc.appendChild(document.createTextNode(vals[y]));
					with(cc.style){
						borderBottom = "1px solid gray";
						paddingLeft = paddingRight = "5px";
						if(x%2){
							backgroundColor = "#e1f1ff";
						}
						if(y>0){
							textAlign = "right";
							borderRight = "1px solid gray";
						}else{
							borderRight = "1px solid black";
						}
					}
				}
			}
		}

		if(appendToDoc){
			var ne = document.createElement("div");
			ne.id = "profileOutputTable";
			with(ne.style){
				fontFamily = "Courier New, monospace";
				fontSize = "12px";
				lineHeight = "16px";
				borderTop = "1px solid black";
				padding = "10px";
			}
			if(document.getElementById("profileOutputTable")){
				document.body.replaceChild(ne, document.getElementById("profileOutputTable"));
			}else{
				document.body.appendChild(ne);
			}
			ne.appendChild(tbl);
		}

		return tbl;
	}
}
