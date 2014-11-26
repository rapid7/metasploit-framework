/* DLLHijackAuditKit (C) 2010 Rapid7, Inc */

function print_status(msg) {
	try {
		WScript.StdOut.WriteLine("[*] "+ msg);
	} catch(e) {}
}

function process_list() {
	var res = new Array();
	var wbemFlagReturnImmediately = 0x10;
	var wbemFlagForwardOnly = 0x20;
	var oWMI = GetObject("winmgmts:\\\\localhost\\root\\CIMV2");
	var cPID = oWMI.ExecQuery("SELECT * FROM Win32_Process", "WQL", wbemFlagReturnImmediately | wbemFlagForwardOnly);
	var enumItems = new Enumerator(cPID);
	for (; !enumItems.atEnd(); enumItems.moveNext()) {
		var p = enumItems.item();
		if (p.ExecutablePath && p.ExecutablePath.toLowerCase().indexOf("taskmgr") != -1) continue;
		res.push(p.ProcessId);
	}
	return res;
}



var pause_interval = 100000;

var oFso = new ActiveXObject("Scripting.FileSystemObject");
var oShl = new ActiveXObject("WScript.Shell");
var oLoc = new ActiveXObject("WbemScripting.SWbemLocator");
var oSvc = oLoc.ConnectServer(null, "root\\default");
var oReg = oSvc.Get("StdRegProv");

var oCWD = oShl.CurrentDirectory + "";

var oMethod = oReg.Methods_.Item("EnumKey");
var oInParam = oMethod.InParameters.SpawnInstance_();
oInParam.hDefKey = 0x80000002;
oInParam.sSubKeyName = "Software\\Classes";

var oOutParam = oReg.ExecMethod_(oMethod.Name, oInParam);
var aNames = oOutParam.sNames.toArray();


try { oFso.CreateFolder("DLLAudit"); } catch(e) { }
try { oFso.CreateFolder("DLLAudit\\ext"); } catch(e) { }


if (! oFso.FileExists("procmon.exe")) {
	print_status("Downloading procmon.exe from \\\\live.sysinternals.com ...")
	try { oFso.CopyFile("\\\\live.sysinternals.com\\Tools\\procmon.exe", "procmon.exe"); } catch(e) {}
}

if (! oFso.FileExists("procmon.exe")) {
	print_status("Failed to download procmon.exe, copy here manually.");
	WScript.Quit();
}


print_status("Starting the process monitor...");
oShl.Run("procmon.exe /AcceptEULA /Quiet /LoadConfig DLLAudit.pmc", 10);
WScript.Sleep(5000);

var total = 0;
print_status("Creating test cases for each file extension...");

for (var i = 0; i < aNames.length; i++) {
	if (aNames[i].substr(0,1) != ".") continue;
	var ext = aNames[i].substr(1,32).toLowerCase();

	if (ext == "com") continue;
	if (ext == "pif") continue;
	if (ext == "exe") continue;
	if (ext == "bat") continue;
	if (ext == "scr") continue;
	if (ext == "dos") continue;
	if (ext == "386") continue;
	if (ext == "cpl") continue;
	if (ext == "sys") continue;
	if (ext == "dll") continue;
	if (ext == "drv") continue;
	if (ext == "rb") continue;
	if (ext == "py") continue;
	if (ext == "pl") continue;
	if (ext == "crds") continue;
	if (ext == "crd") continue;
	if (ext == "pml") continue;
	if (ext == "pmc") continue;

	try { oFso.CreateFolder("DLLAudit\\ext\\" + ext); } catch(e) { }
	try {
		var a = oFso.CreateTextFile("DLLAudit\\ext\\" + ext + "\\exploit." + ext);
		a.WriteLine("HOWDY!");
		a.Close();
	} catch(e) { }

	total++;
}

print_status("Created " + total + " test cases");
var procs = process_list();
print_status("Protecting " + procs.length + " processes");

var tries = 0;

var base = oFso.GetFolder("DLLAudit\\ext");
var subs = new Enumerator(base.SubFolders);
for (; !subs.atEnd(); subs.moveNext()) {
	var path = subs.item() + "";
	var bits = path.split("\\");
	var ext  = bits[bits.length - 1];

	print_status("Auditing extension: " + ext);
	oShl.CurrentDirectory = path + "\\";

	oShl.Run("cmd.exe /c start exploit." + ext, 0);
	WScript.Sleep(500);

	var nprocs = process_list();
	var cnt = 0;
	while(nprocs.length == procs.length && cnt < 2) {
		cnt++;
		WScript.Sleep(500);
		nprocs = process_list();
	}

	// If an application spawned, give it three seconds
	// This helps with ProcMon memory usage as well
	if (nprocs.length > procs.length) {
		WScript.Sleep(3000);
	}

	var killer = "taskkill /F ";
	for (var i=0; i < nprocs.length; i++) {
		var found = false;
		for (var x=0; x < procs.length; x++) {
			if (nprocs[i] == procs[x]) {
				found = true;
				break;
			}
		}
		if (found) continue;
		killer = killer + "/PID " + nprocs[i] + " ";
	}
	oShl.Run(killer, 0, true);

	tries++;

	if (tries % pause_interval == 0) {
		print_status("Completed " + tries + " extensions, hit enter to continue.")
		WScript.Stdin.ReadLine();
		print_status("Continuing...")
	}
}

print_status("Data collection phase complete, export Logfile.CSV from ProcMon.")

