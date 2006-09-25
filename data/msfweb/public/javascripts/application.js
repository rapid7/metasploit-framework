/*
 * Copyright (c) 2006, L.M.H. <lmh@info-pull.>
 * All Rights Reserved.
 */

var about_dlg;

function help_functions(e) {
	about_dlg = dojo.widget.byId("AboutDialog");
	var btn = document.getElementById("hidedialog");
	about_dlg.setCloseControl(btn);
}

dojo.addOnLoad(help_functions);