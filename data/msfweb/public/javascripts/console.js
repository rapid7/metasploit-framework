/* web msfconsole (console.js)
 * Copyright (c) 2006 LMH <lmh@info-pull.com>
 * All Rights Reserved.
 * Inspired by Jesse Ruderman's Javascript Shell.
*/

var console_history = new Array();  // Commands history
var console_hindex  = 0;            // Index to current command history
var console_input;                  // Object to console input
var console_output;                 // Object to console output
var console_prompt;                 // Object to console prompt

// Placeholders
var con_prompt = "";
var con_update = "";
var con_tabbed = "";


function console_refocus() {
    console_input.blur();
    console_input.focus();
}

function console_printline(s, type) {
    if ((s=String(s))) {
        var n = document.createElement("div");
        n.appendChild(document.createTextNode(s));
        n.className = type;
        console_output.appendChild(n);
        return n;
    }
}

function console_update_output(req) {
	
	try { eval(req.responseText); } catch(e){ alert(req.responseText); }
	
	window.status = "";
		
	console_printline(con_update);
	console_prompt.innerHTML = con_prompt;
	console_refocus();

}

function console_update_tabs(req) {
	try { eval(req.responseText); } catch(e){ console_output.innerHTML = req.responseText; }
	
	window.status = "";
	console_printline(con_update);
	console_prompt.innerHTML = con_prompt;
	console_input.value = con_tabbed;
	
	console_refocus();
}

function console_keypress(e) {
	if (e.keyCode == 13) {          // enter
        console_history.push(console_input.value);
		
		console_printline("\n" + con_prompt + ' ' + console_input.value)
		
		window.status = "Executing command, please wait..."
		
		new Ajax.Updater("console_update", document.location, {
			asynchronous:true,
			evalScripts:true,
			parameters:"cmd=" + escape(console_input.value),
			onComplete:console_update_output
		});	

		console_input.value = "";
		console_input.focus();
		return false;
	}
		
}


function console_keydown(e) {

    if (e.keyCode == 38) {   // up
        // TODO: place upper cmd in history on console_input.value
		alert('UP');
    } else if (e.keyCode == 40) {   // down
        // TODO: place lower cmd in history on console_input.value
		alert('DOWN');
    } else if (e.keyCode == 9) {   // tab
		window.status = "Finding possible commands..."
		new Ajax.Updater("console_update", document.location, {
			asynchronous:true,
			evalScripts:true,
			parameters:"tab=" + escape(console_input.value),
			onComplete:console_update_tabs
		});	
    }

}

function console_init() {

    console_input   = document.getElementById("console_input");
    console_output  = document.getElementById("console_output");
	console_prompt  = document.getElementById("console_prompt");
	
	console_refocus();
	
    return true;
}

