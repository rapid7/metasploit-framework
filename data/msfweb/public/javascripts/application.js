/*
 * Copyright (c) 2006, L.M.H. <lmh@info-pull.>
 * All Rights Reserved.
 */

var about_dlg;
var main_Pane;

function helper_functions(e) {
	about_dlg = dojo.widget.byId("AboutDialog");
	main_Pane = dojo.widget.byId("maincontent");
	var btn = document.getElementById("hidedialog");
	about_dlg.setCloseControl(btn);
}

dojo.addOnLoad(helper_functions);