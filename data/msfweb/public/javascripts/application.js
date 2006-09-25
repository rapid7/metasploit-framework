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

/* Description: Simple window management code.
 * Thanks: tk and dmachi for suggestions
 */

function load_stateful_window(target_url, nid, ntitle, nstyle) {
    // create new floating pane (window)
    var new_window = create_new_window(nid, ntitle, nstyle, "normal", "maintaskbar");
    // create new content pane
    var new_contentpane = dojo.widget.createWidget("ContentPane", {href: target_url});
    // add new content pane to new floating pane as child
    new_window.addChild(new_contentpane);
    // add new floating pane to main pane
    main_Pane.addChild(new_window);
}

function create_new_window(window_id, window_title, window_style, window_state, target_taskbar) {
    var myNewFloatingPane = dojo.widget.createWidget("FloatingPane",
        {
            /* floating pane params */
            id: window_id,
            title: window_title,
            constrainToContainer: "true",
            hasShadow: "false",
            resizable: "true",
            taskBarId: target_taskbar,
            windowState: window_state,
            displayCloseAction: "true",
            displayMinimizeAction: "true",
            toggle: "explode",
            style: window_style
        });
    
    return myNewFloatingPane;
}

function generate_window_style(width, height) {
    var generic_css = "position: relative;" +
                      "left: 100px;" +
                      "top: 35px;" +
                      "display:none;" +
                      "width: " + width +"px;" +
                      "height: "+ height +"px;"
    return generic_css;
}

dojo.addOnLoad(helper_functions);