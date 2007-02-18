/* 
 * Copyright (c) 2006 LMH <lmh[at]info-pull.com>
 * Added to Metasploit under the terms of the Metasploit Framework License v1.2
 * Additions Copyright (C) 2006-2007 Metasploit LLC
*/


var console_id;
var console_history = new Array();  // Commands history
var console_hindex  = 0;            // Index to current command history
var console_input;                  // Object to console input
var console_output;                 // Object to console output
var console_prompt;                 // Object to console prompt
var console_status;
var console_cmdbar;

// Placeholders
var con_prompt = "";
var con_update = "";
var con_tabbed = "";



// Internal commands
var cmd_internal = 
{
	clear:function() {
		console_output.innerHTML = '';
	}
};

function status_busy() {
	console_input.style.color = "red";
}

function status_free() {
	console_input.style.color = "white";
}

// This function is based on the excellent example:
// http://tryruby.hobix.com/js/mouseApp.js
function keystroke_block(e) {
	e.cancelBubble=true;
	e.returnValue = false;
	if (window.event && !window.opera) e.keyCode=0;
	if (e.stopPropagation) e.stopPropagation();
	if (e.preventDefault)  e.preventDefault();
	return false;
}

function console_refocus() {
    console_input.blur();
    console_input.focus();
}

function console_read() {
	new Ajax.Updater("console_update", '/_console/cid=' + console_id, {
		asynchronous:true,
		evalScripts:true,
		onComplete:console_read_output
	});	
}


function console_printline(s, type) {
    if ((s=String(s))) {
        var n = document.createElement("div");
		
		// IE has to use innerText
		if (n.innerText != undefined) {
			n.innerText = s;
		// Firefox uses createTextNode
		} else {
	        n.appendChild(document.createTextNode(s));
		}
		
        n.className = type;
        console_output.appendChild(n);
        return n;
    }
}

function console_read_output(req) {
	// Call the console updated
	console_update_output(req);
	
	// Reschedule the console reader
	setTimeout(console_read, 1);
}

function console_update_output(req) {
	
	try { eval(req.responseText); } catch(e){ alert(req.responseText); }
	
	status_free();
		
	if (con_update.length > 0) {
		console_printline(con_update, 'output_line');
	}
	
	console_prompt.innerHTML = con_prompt;
	console_refocus();
	

}

function console_update_tabs(req) {
	try { eval(req.responseText); } catch(e){ console_output.innerHTML = req.responseText; }
	
	status_free();
	
	console_printline(con_update, 'output_line');
	console_prompt.innerHTML = con_prompt;
	console_input.value = con_tabbed;
	
	console_refocus();
}

function console_keypress(e) {
	if (e.keyCode == 13) {          // enter
        
		console_input.value = (console_input.value.replace(/^ +/,'')).replace(/ +$/,'');
		
		// ignore duplicate commands in the history
		if(console_history[console_history.length-1] != console_input.value) {		
			console_history.push(console_input.value);
			console_hindex = console_history.length - 1;
		}
		
		console_printline("\n>> " + console_input.value + "\n\n", 'output_line')
		
		if(cmd_internal[console_input.value]) {
			cmd_internal[console_input.value]();
			console_input.value = "";
			console_input.focus();			
			return keystroke_block(e);
		}
		
		status_busy();
		
		new Ajax.Updater("console_update", document.location, {
			asynchronous:true,
			evalScripts:true,
			parameters:"cmd=" + escape(console_input.value),
			onComplete:console_update_output
		});	

		console_input.value = "";
		console_input.focus();
		return keystroke_block(e);
	}
		
}


function console_keydown(e) {
	
    if (e.keyCode == 38) {   // up
        // TODO: place upper cmd in history on console_input.value

		console_input.value = console_history[console_hindex];
		if (console_hindex > 0) {
			console_hindex--;
		}
		
		return keystroke_block(e);
		
    } else if (e.keyCode == 40) {   // down
		
		if (console_hindex < console_history.length - 1) {
			console_hindex++;
		}
		console_input.value = console_history[console_hindex];
		
		return keystroke_block(e);
		
    } else if (e.keyCode == 9) {   // tab
		
		status_busy();
					
		new Ajax.Updater("console_update", document.location, {
			asynchronous:true,
			evalScripts:true,
			parameters:"tab=" + escape(console_input.value),
			onComplete:console_update_tabs
		});	
		return keystroke_block(e);
    }

}

function console_init(cid) {

	console_id      = cid;
    console_input   = document.getElementById("console_input");
    console_output  = document.getElementById("console_output");
	console_prompt  = document.getElementById("console_prompt");
	console_status  = document.getElementById("console_status");
	console_cmdbar  = document.getElementById("console_command_bar");
	
	console_refocus();
	status_free();
	
	console_read();
	
    return true;
}

