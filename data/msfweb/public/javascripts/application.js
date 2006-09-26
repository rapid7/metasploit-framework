/*
 * Copyright (c) 2006, L.M.H. <lmh@info-pull.>
 * All Rights Reserved.
 */

/*
 * Dialogs
 */

function openAboutDialog() {
    // ...
}

function openExploitWindow() {
    var exploitList = create_window_ajax("/exploits/list", "exploits-list", "Available Exploits", '700', '300');
    exploitList.setDestroyOnClose();
    exploitList.showCenter();
}

function openPayloadsWindow() {
    var payloadList = create_window_ajax("/payloads/list", "payloads-list", "Available Payloads", '500', '300');
    payloadList.setDestroyOnClose();
    payloadList.showCenter();
}

function openEncodersWindow() {
    var encoderList = create_window_ajax("/encoders/list", "encoders-list", "Available Encoders", '300', '200');
    encoderList.setDestroyOnClose();
    encoderList.showCenter();
}

function openNopsWindow() {
    var nopsList = create_window_ajax("/nops/list", "nops-list", "Available Nops", '300', '200');
    nopsList.setDestroyOnClose();
    nopsList.showCenter();
}

function openJobsWindow() {
    var nopsList = create_window_ajax("/jobs/list", "jobs-list", "Current Jobs", '300', '200');
    jobsList.setDestroyOnClose();
    jobsList.showCenter();
}

function openSessionsWindow() {
    var sessionsList = create_window_ajax("/sessions/list", "sessions-list", "Active Sessions", '300', '200');
    sessionsList.setDestroyOnClose();
    sessionsList.showCenter();
}

/*
 * Task and helper functions
 */

function create_window_ajax(target_url, wid, wtitle, wwidth, wheight) {
    var new_mwindow = new Window(wid,
        { className: "metasploit",
          title: wtitle,
          top:70,
          left:100,
          width:wwidth,
          height:wheight,
          resizable: true,
          draggable: true,
          url: target_url,
          showEffectOptions:
            {
                duration:0.5
            }
          });
    return new_mwindow;
}

function run_tasks() {
    // ...
}