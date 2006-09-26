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
    var exploitList = create_window_ajax("/exploits/list", "exploits-list", "Available Exploits", 600, 300);
    exploitList.setDestroyOnClose();
    exploitList.showCenter();
}

function openAuxiliariesWindow() {
    var auxList = create_window_ajax("/auxiliaries/list", "auxiliaries-list", "Auxiliary Modules", 600, 300);
    auxList.setDestroyOnClose();
    auxList.showCenter();
}

function openPayloadsWindow() {
    var payloadList = create_window_ajax("/payloads/list", "payloads-list", "Available Payloads", 600, 300);
    payloadList.setDestroyOnClose();
    payloadList.showCenter();
}

function openEncodersWindow() {
    var encoderList = create_window_ajax("/encoders/list", "encoders-list", "Available Encoders", 600, 300);
    encoderList.setDestroyOnClose();
    encoderList.showCenter();
}

function openNopsWindow() {
    var nopList = create_window_ajax("/nops/list", "nops-list", "Available No-Op Generators", 600, 300);
    nopList.setDestroyOnClose();
    nopList.showCenter();
}

function openSessionsWindow() {
    var sessionList = create_window_ajax("/sessions/list", "sessions-list", "Metasploit Sessions", 600, 300);
    sessionList.setDestroyOnClose();
    sessionList.showCenter();
}

function openJobsWindow() {
    var jobList = create_window_ajax("/jobs/list", "jobs-list", "Running Jobs", 600, 300);
    jobList.setDestroyOnClose();
    jobList.showCenter();
}

/*
 * Task and helper functions
 */

function create_window_ajax(target_url, wid, wtitle, wwidth, wheight) {
    var new_mwindow = new Window(wid+'-'+obtainWindowId(),
        { className: "metasploit",
          title: wtitle,
          top:70,
          left:100,
          width:wwidth,
          height:wheight,
          resizable: true,
          draggable: true,
          url: target_url,
          showEffectOptions: { duration: 0.25 },
          hideEffectOptions: { duration: 0.25 }
          });
    return new_mwindow;
}

function openModuleWindow(mtype, refname, wtitle) {
    var mWin = create_window_ajax("/" + mtype + "/view/" + refname, mtype + "-view-" + obtainWindowId(), wtitle, 400, 300);
    mWin.setDestroyOnClose();
    mWin.showCenter();
}

function run_tasks() {
    // ...
}
