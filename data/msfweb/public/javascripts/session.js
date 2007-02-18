/* 
 * Copyright (c) 2006 LMH <lmh[at]info-pull.com>
 * Added to Metasploit under the terms of the Metasploit Framework License v1.2
 * Additions Copyright (C) 2006-2007 Metasploit LLC
*/


var session_id;
var session_history = new Array();  // Commands history
var session_hindex  = 0;            // Index to current command history
var session_input;                  // Object to console input
var session_output;                 // Object to console output
var session_prompt;                 // Object to console prompt
var session_status;
var session_cmdbar;

// Placeholders
var ses_prompt = "";
var ses_update = "";
var ses_tabbed = "";



// Internal commands
var cmd_internal = 
{
	help:function() {
		session_printline("     Web Session Internal Commands\n");
		session_printline("=========================================\n\n");
		session_printline(" /help       Show this text\n");
		session_printline(" /clear      Clear the screen\n");
		session_printline(" /detach     Detach an active session\n");
		session_printline(" /kill       Abort an active session\n");
		session_printline("\n");
	},
	clear:function() {
		session_output.innerHTML = '';
	},
	detach:function() {
		session_printline(">> Detaching active session...\n");
		new Ajax.Updater("session_update", document.location, {
			asynchronous:true,
			evalScripts:true,
			parameters:"special=detach"
		});		
	},
	kill:function() {
		session_printline(">> Killing active session...\n");	
		new Ajax.Updater("session_update", document.location, {
			asynchronous:true,
			evalScripts:true,
			parameters:"special=kill"
		});			
	}
};

function status_busy() {
	session_input.style.color = "red";
}

function status_free() {
	session_input.style.color = "white";
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

function session_refocus() {
    session_input.blur();
    session_input.focus();
}

function session_read() {
	new Ajax.Updater("session_update", document.location, {
		asynchronous:true,
		evalScripts:true,
		parameters:"read=yes",
		onComplete:session_read_output
	});	
}


function session_printline(s, type) {
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
        session_output.appendChild(n);
        return n;
    }
}

function session_read_output(req) {
	// Call the console updated
	session_update_output(req);
	
	// Reschedule the session reader
	setTimeout(session_read, 1000);
}

function session_update_output(req) {
	
	try { eval(req.responseText); } catch(e){ alert(req.responseText); }
	
	status_free();
		
	if (ses_update.length > 0) {
		session_printline(ses_update, 'output_line');
	}
	
	session_refocus();
}


function session_keypress(e) {
	if (e.keyCode == 13) {          // enter
        
		session_input.value = (session_input.value.replace(/^ +/,'')).replace(/ +$/,'');
		
		// ignore duplicate commands in the history
		if(session_history[session_history.length-1] != session_input.value) {		
			session_history.push(session_input.value);
			session_hindex = session_history.length - 1;
		}
		
		session_printline("\n>> " + session_input.value + "\n\n", 'output_line')
		
		if(session_input.value[0] == '/') {
			cmd_name = session_input.value.substring(1);
			
			if(cmd_internal[cmd_name]) {
				cmd_internal[cmd_name]();
				session_input.value = "";
				session_input.focus();			
				return keystroke_block(e);
			}
		}
				
		status_busy();
		
		new Ajax.Updater("session_update", document.location, {
			asynchronous:true,
			evalScripts:true,
			parameters:"read=yes&cmd=" + escape(session_input.value),
			onComplete:session_update_output
		});	

		session_input.value = "";
		session_input.focus();
		return keystroke_block(e);
	}
		
}


function session_keydown(e) {
	
    if (e.keyCode == 38) {   // up
        // TODO: place upper cmd in history on session_input.value

		session_input.value = session_history[session_hindex];
		if (session_hindex > 0) {
			session_hindex--;
		}
		
		return keystroke_block(e);
		
    } else if (e.keyCode == 40) {   // down
		
		if (session_hindex < session_history.length - 1) {
			session_hindex++;
		}
		session_input.value = session_history[session_hindex];
		
		return keystroke_block(e);
		
    }

}

function session_init(cid) {

	session_id      = cid;
    session_input   = document.getElementById("session_input");
    session_output  = document.getElementById("session_output");
	session_prompt  = document.getElementById("session_prompt");
	session_status  = document.getElementById("session_status");
	session_cmdbar  = document.getElementById("session_command_bar");
	
	session_refocus();
	status_free();
	
	session_read();
	
    return true;
}

