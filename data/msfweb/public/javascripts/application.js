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


function openAboutDialog() {}

function run_tasks() {
    initialize_topmenu();
}