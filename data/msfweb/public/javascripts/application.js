/*
 * Copyright (c) 2006, L.M.H. <lmh@info-pull.>
 * All Rights Reserved.
 */

/*
 * Dialogs
 */


var winIndex = 0;
/* Returns a unique Window identifier */
function obtainWindowId() {
	return(winIndex++);
}

function openAboutDialog() {
    // ...
}


function openExploitsWindow() {
    var exploitList = create_window_ajax("/exploits/list", "exploits-list-"+obtainWindowId(), "Available Exploits");
    exploitList.setDestroyOnClose();
    exploitList.showCenter();
}

function openAuxiliariesWindow() {
    var auxList = create_window_ajax("/auxiliaries/list", "auxiliaries-list-"+obtainWindowId(), "Auxiliary Modules");
    auxList.setDestroyOnClose();
    auxList.showCenter();
}

function openPayloadsWindow() {
    var payloadList = create_window_ajax("/payloads/list", "payloads-list-"+obtainWindowId(), "Available Payloads");
    payloadList.setDestroyOnClose();
    payloadList.showCenter();
}

function openEncodersWindow() {
    var encoderList = create_window_ajax("/encoders/list", "encoders-list-"+obtainWindowId(), "Available Encoders");
    encoderList.setDestroyOnClose();
    encoderList.showCenter();
}

function openNopsWindow() {
    var nopList = create_window_ajax("/nops/list", "nops-list-"+obtainWindowId(), "Available No-Op Generators");
    nopList.setDestroyOnClose();
    nopList.showCenter();
}

function openSessionsWindow() {
    var sessionList = create_window_ajax("/sessions/list", "sessions-list-"+obtainWindowId(), "Metasploit Sessions");
    sessionList.setDestroyOnClose();
    sessionList.showCenter();
}

function openJobsWindow() {
    var jobList = create_window_ajax("/jobs/list", "jobs-list-"+obtainWindowId(), "Running Jobs");
    jobList.setDestroyOnClose();
    jobList.showCenter();
}

function openModuleWindow(mtype, refname, wtitle) {
    var mWin = create_window_ajax("/" + mtype + "/view/" + refname, mtype + "-view-" + obtainWindowId(), wtitle);
    mWin.setDestroyOnClose();
    mWin.showCenter();
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
          width:600,
          height:400,

          resizable: true,
          draggable: true,
          url: target_url,
          showEffectOptions:
            {
                duration: 0.25
            }
          });
    return new_mwindow;
}

function run_tasks() {
    // ...
}
