/*
 * Copyright (c) 2006, L.M.H. <lmh@info-pull.>
 * All Rights Reserved.
 */

/* http://alistapart.com/articles/dropdowns/ */
function initialize_topmenu() {
	if (document.all&&document.getElementById) {
		navRoot = document.getElementById("topmenu");
		for (i=0; i<navRoot.childNodes.length; i++) {
			node = navRoot.childNodes[i];
			if (node.nodeName=="LI") {
				node.onmouseover=function() {
					this.className+=" over";
				}
				node.onmouseout=function() {
					this.className=this.className.replace(" over", "");
				}
			}
		}
	}
}


function openAboutDialog() {
   win = new Window('window_id', {className: "mac_os_x", title: "Sample", width:200, height:150}); win.getContent().innerHTML = "<h1>Hello world !!</h1>"; win.setDestroyOnClose(); win.showCenter(); 
   }
function fade_start_tip() {
    new Effect.Fade('starttip', {duration: 4});
}

function run_tasks() {
    //fade_start_tip();
    //initialize_topmenu();
}