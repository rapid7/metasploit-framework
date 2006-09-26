/*
 * Copyright (c) 2006, L.M.H. <lmh@info-pull.>
 * All Rights Reserved.
 */

/*
 * Dialogs
 */

function openAboutDialog() {

}

function openExploitWindow() {
    var exploitList = create_window_ajax("/exploits/list", "exploits-list", "Available Exploits");
    exploitList.setDestroyOnClose();
    exploitList.showCenter();
}

function openPayloadsWindow() {
    var payloadList = create_window_ajax("/payloads/list", "payloads-list", "Available Payloads");
    payloadList.setDestroyOnClose();
    payloadList.showCenter();
}

/*
 * Task and helper functions
 */

function create_window_ajax(target_url, wid, wtitle) {
    var new_mwindow = new Window(wid,
        { className: "metasploit",
          title: wtitle,
          top:70,
          left:100,
          width:300,
          height:200,
          resizable: true,
          draggable: true,
          url: target_url,
          showEffectOptions:
            {
                duration:3
            }
          });
    return new_mwindow;
}

function run_tasks() {
    // ...
}