/* web msfconsole (console.js)
 * Copyright (c) 2006 LMH <lmh@info-pull.com>
 * All Rights Reserved.
 * Inspired by Jesse Ruderman's Javascript Shell.
*/

var console_history = new Array();  // Commands history
var console_hindex  = 0;            // Index to current command history
var console_input;                  // Object to console input
var console_output;                 // Object to console output

function console_refocus() {}
function console_tabcomplete() {
    // TODO: 
}

function console_execute() {}

function console_keydown(e) {
    if (e.keyCode == 13) {          // enter
        console_history.push(console_input.value);
        try { console_execute(); } catch(er) { alert(er); };
        setTimeout(function() { console_input.value = ""; }, 0);
    } else if (e.keyCode == 38) {   // up
        // TODO: place upper cmd in history on console_input.value
    } else if (e.keyCode == 40) {   // down
        // TODO: place lower cmd in history on console_input.value
    } else if (e.keyCode == 9) {   // tab
        console_tabcomplete();
        setTimeout(function() { console_refocus(); }, 0);
    }
}

function console_init() {

    console_input   = document.getElementById("console_input");
    console_output  = document.getElementById("console_output");

    return true;
}

