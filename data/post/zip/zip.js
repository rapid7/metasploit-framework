/*
 * Original technique from http://naterice.com/zip-and-unzip-files-using-the-windows-shell-and-vbscript/
 */

function create_zip(dst)
{
	var header = "\x50\x4b\x05\x06" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	/*
	 * Trick to write a binary file regardless of the system locale
	 */
	var outw = new ActiveXObject("ADODB.Stream");
	outw.Type = 2;
	outw.Open();
	outw.WriteText(header);
	outw.Position = 0;

	var outa = new ActiveXObject("ADODB.Stream");
	outa.Type = 2;
	outa.Charset = "windows-1252";
	outa.Open()

	outw.CopyTo(outa);
	outa.SaveToFile(dst, 2);

	outw.Close();
	outa.Close();
}

function basename(path)
{
	var a = path.split("\\");
	var b = a.slice(-1);
	return b[0];
}

function fileeq(a, b)
{
	return basename(a).toLowerCase() == basename(b).toLowerCase();
}

function zip(src, dst)
{
	var shell = new ActiveXObject('Shell.Application');
	var fso = new ActiveXObject('Scripting.FileSystemObject');

	/*
	 * Normalize paths, required by the shell commands
	 */
	src = fso.GetAbsolutePathName(src);
	dst = fso.GetAbsolutePathName(dst);

	/*
	 * Create an empty zip file if necessary
	 */
	if (!fso.FileExists(dst)) {
		create_zip(dst);
	}

	/*
	 * Check for duplicates
	 */
	var zipfile = shell.Namespace(dst);
	var files = zipfile.items();
	var count = files.Count;
	for (var i = 0; i < files.Count; i++) {
		if (fileeq(files.Item(i).Name, src)) {
			return;
		}
	}

	zipfile.CopyHere(src);

	/*
	 * Wait for completion, but data can be stale on network shares, so we
	 * abort after 5 seconds.
	 */
	var max_tries = 50;
	while (count == zipfile.items().Count) {
		WScript.Sleep(100);
		if (max_tries-- == 0) {
			return;
		}
	}
}
