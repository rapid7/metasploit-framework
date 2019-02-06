# -*- coding: binary -*-
require 'rex'
require 'rex/ui/text/output/buffer'

module Msf
module RPC
class RPC_Session < RPC_Base

  # Returns a list of sessions that belong to the framework instance used by the RPC service.
  #
  # @return [Hash] Information about sessions. Each key is the session ID, and each value is a hash
  #                that contains the following:
  #                * 'type' [String] Payload type. Example: meterpreter.
  #                * 'tunnel_local' [String] Tunnel (where the malicious traffic comes from).
  #                * 'tunnel_peer' [String] Tunnel (local).
  #                * 'via_exploit' [String] Name of the exploit used by the session.
  #                * 'desc' [String] Session description.
  #                * 'info' [String] Session info (most likely the target's computer name).
  #                * 'workspace' [String] Name of the workspace.
  #                * 'session_host' [String] Session host.
  #                * 'session_port' [Integer] Session port.
  #                * 'target_host' [String] Target host.
  #                * 'username' [String] Username.
  #                * 'uuid' [String] UUID.
  #                * 'exploit_uuid' [String] Exploit's UUID.
  #                * 'routes' [String] Routes.
  #                * 'platform' [String] Platform.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.list')
  def rpc_list
    res = {}
    self.framework.sessions.each do |sess|
      i,s = sess
      res[s.sid] = {
        'type'         => s.type.to_s,
        'tunnel_local' => s.tunnel_local.to_s,
        'tunnel_peer'  => s.tunnel_peer.to_s,
        'via_exploit'  => s.via_exploit.to_s,
        'via_payload'  => s.via_payload.to_s,
        'desc'         => s.desc.to_s,
        'info'         => s.info.to_s,
        'workspace'    => s.workspace.to_s,
        'session_host' => s.session_host.to_s,
        'session_port' => s.session_port.to_i,
        'target_host'  => s.target_host.to_s,
        'username'     => s.username.to_s,
        'uuid'         => s.uuid.to_s,
        'exploit_uuid' => s.exploit_uuid.to_s,
        'routes'       => s.routes.join(","),
        'arch'         => s.arch.to_s
      }
      if(s.type.to_s == "meterpreter")
        res[s.sid]['platform'] = s.platform.to_s
      end
    end
    res
  end


  # Stops a session.
  #
  # @param [Integer] sid Session ID.
  # @raise [Msf::RPC::Exception] Unknown session ID.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] A message that says 'success'.
  def rpc_stop( sid)

    s = self.framework.sessions[sid.to_i]
    if(not s)
      error(500, "Unknown Session ID")
    end
    s.kill rescue nil
    { "result" => "success" }
  end


  # Reads the output of a shell session (such as a command output).
  #
  # @param [Integer] sid Session ID.
  # @param [Integer] ptr Pointer.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  #                              * 500 Session is disconnected.
  # @return [Hash] It contains the following keys:
  #  * 'seq' [String] Sequence.
  #  * 'data' [String] Read data.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.shell_read', 2)
  def rpc_shell_read( sid, ptr=nil)
    s = _valid_session(sid,"shell")
    begin
      res = s.shell_read()
      { "seq" => 0, "data" => res.to_s}
    rescue ::Exception => e
      error(500, "Session Disconnected: #{e.class} #{e}")
    end
  end


  # Writes to a shell session (such as a command). Note that you will to manually add a newline at the
  # enf of your input so the system will process it.
  # You may want to use #rpc_shell_read to retrieve the output.
  #
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  #                              * 500 Session is disconnected.
  # @param [Integer] sid Session ID.
  # @param [String] data The data to write.
  # @return [Hash]
  #  * 'write_count' [Integer] Number of bytes written.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.shell_write', 2, "DATA")
  def rpc_shell_write( sid, data)
    s = _valid_session(sid,"shell")
    begin
      res = s.shell_write(data)
      { "write_count" => res.to_s}
    rescue ::Exception => e
      error(500, "Session Disconnected: #{e.class} #{e}")
    end
  end


  # Upgrades a shell to a meterpreter.
  #
  # @note This uses post/multi/manage/shell_to_meterpreter.
  # @param [Integer] sid Session ID.
  # @param [String] lhost Local host.
  # @param [Integer] lport Local port.
  # @return [Hash] A hash indicating the actioin was successful. It contains the following key:
  #  * 'result' [String] A message that says 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('session.shell_upgrade', 2, payload_lhost, payload_lport)
  def rpc_shell_upgrade( sid, lhost, lport)
    s = _valid_session(sid,"shell")
    s.exploit_datastore['LHOST'] = lhost
    s.exploit_datastore['LPORT'] = lport
    s.execute_script('post/multi/manage/shell_to_meterpreter')
    { "result" => "success" }
  end


  # Reads the output from a meterpreter session (such as a command output).
  #
  # @note Multiple concurrent callers writing and reading the same Meterperter session can lead to
  #  a conflict, where one caller gets the others output and vice versa. Concurrent access to a
  #  Meterpreter session is best handled by post modules.
  # @param [Integer] sid Session ID.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] It contains the following key:
  #  * 'data' [String] Data read.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.meterpreter_read', 2)
  def rpc_meterpreter_read( sid)
    s = _valid_session(sid,"meterpreter")

    if not s.user_output.respond_to? :dump_buffer
      s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
    end

    data = s.user_output.dump_buffer
    { "data" => data }
  end


  # Reads from a session (such as a command output).
  #
  # @param [Integer] sid Session ID.
  # @param [Integer] ptr Pointer (ignored)
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  #                              * 500 Session is disconnected.
  # @return [Hash] It contains the following key:
  #  * 'seq' [String] Sequence.
  #  * 'data' [String] Read data.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.ring_read', 2)
  def rpc_ring_read(sid, ptr = nil)
    s = _valid_session(sid,"ring")
    begin
      res = s.shell_read()
      { "seq" => 0, "data" => res.to_s }
    rescue ::Exception => e
      error(500, "Session Disconnected: #{e.class} #{e}")
    end
  end


  # Sends an input to a session (such as a command).
  #
  # @param [Integer] sid Session ID.
  # @param [String] data Data to write.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  #                              * 500 Session is disconnected.
  # @return [Hash] It contains the following key:
  #  * 'write_count' [String] Number of bytes written.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.ring_put', 2, "DATA")
  def rpc_ring_put(sid, data)
    s = _valid_session(sid,"ring")
    begin
      res = s.shell_write(data)
      { "write_count" => res.to_s}
    rescue ::Exception => e
      error(500, "Session Disconnected: #{e.class} #{e}")
    end
  end

  # Returns the last sequence (last issued ReadPointer) for a shell session.
  #
  # @param [Integer] sid Session ID.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] It contains the following key:
  #  * 'seq' [String] Sequence.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.ring_last', 2)
  def rpc_ring_last(sid)
    s = _valid_session(sid,"ring")
    { "seq" => 0 }
  end


  # Clears a shell session. This may be useful to reclaim memory for idle background sessions.
  #
  # @param [Integer] sid Session ID.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains:
  #  * 'result' [String] Either 'success' or 'failure'.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.ring_clear', 2)
  def rpc_ring_clear(sid)
    { "result" => "success" }
  end


  # Sends an input to a meterpreter prompt.
  # You may want to use #rpc_meterpreter_read to retrieve the output.
  #
  # @note Multiple concurrent callers writing and reading the same Meterperter session can lead to
  #  a conflict, where one caller gets the others output and vice versa. Concurrent access to a
  #  Meterpreter session is best handled by post modules.
  # @param [Integer] sid Session ID.
  # @param [String] data Input to the meterpreter prompt.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] A hash indicating the action was successful or not. It contains the following key:
  #  * 'result' [String] Either 'success' or 'failure'.
  # @see #rpc_meterpreter_run_single
  # @example Here's how you would use this from the client:
  #  rpc.call('session.meterpreter_write', 2, "sysinfo")
  def rpc_meterpreter_write( sid, data)
    s = _valid_session(sid,"meterpreter")

    if not s.user_output.respond_to? :dump_buffer
      s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
    end

    interacting = false
    s.channels.each_value do |ch|
      interacting ||= ch.respond_to?('interacting') && ch.interacting
    end
    if interacting
      s.user_input.put(data + "\n")
    else
      self.framework.threads.spawn("MeterpreterRunSingle", false, s) { |sess| sess.console.run_single(data) }
    end
    { "result" => "success" }
  end


  # Detaches from a meterpreter session. Serves the same purpose as [CTRL]+[Z].
  #
  # @param [Integer] sid Session ID.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] A hash indicating the action was successful or not. It contains:
  #  * 'result' [String] Either 'success' or 'failure'.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.meterpreter_session_detach', 3)
  def rpc_meterpreter_session_detach(sid)
    s = _valid_session(sid,"meterpreter")
    s.channels.each_value do |ch|
      if(ch.respond_to?('interacting') && ch.interacting)
        ch.detach()
        return { "result" => "success" }
      end
    end
    { "result" => "failure" }
  end


  # Kills a meterpreter session. Serves the same purpose as [CTRL]+[C].
  #
  # @param [Integer] sid Session ID.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] A hash indicating the action was successful or not.
  #                It contains the following key:
  #  * 'result' [String] Either 'success' or 'failure'.
  # @example Here's how you would use this from the client:
  #  rpc.call('session.meterpreter_session_kill', 3)
  def rpc_meterpreter_session_kill(sid)
    s = _valid_session(sid,"meterpreter")
    s.channels.each_value do |ch|
      if(ch.respond_to?('interacting') && ch.interacting)
        ch._close
        return { "result" => "success" }
      end
    end
    { "result" => "failure" }
  end


  # Returns a tab-completed version of your meterpreter prompt input.
  #
  # @param [Integer] sid Session ID.
  # @param [String] line Input.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] The tab-completed result. It contains the following key:
  #  * 'tabs' [String] The tab-completed version of your input.
  # @example Here's how you would use this from the client:
  #  # This returns:
  #  # {"tabs"=>["sysinfo"]}
  #  rpc.call('session.meterpreter_tabs', 3, 'sysin')
  def rpc_meterpreter_tabs(sid, line)
    s = _valid_session(sid,"meterpreter")
    { "tabs" => s.console.tab_complete(line) }
  end


  # Runs a meterpreter command even if interacting with a shell or other channel.
  # You will want to use the #rpc_meterpreter_read to retrieve the output.
  #
  # @param [Integer] sid Session ID.
  # @param [String] data Command.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('session.meterpreter_run_single', 3, 'getpid')
  def rpc_meterpreter_run_single( sid, data)
    s = _valid_session(sid,"meterpreter")

    if not s.user_output.respond_to? :dump_buffer
      s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
    end

    self.framework.threads.spawn("MeterpreterRunSingle", false, s) { |sess| sess.console.run_single(data) }
    { "result" => "success" }
  end


  # Runs a meterpreter script.
  #
  # @deprecated Metasploit no longer maintains or accepts meterpreter scripts. Please try to use
  #             post modules instead.
  # @see Msf::RPC::RPC_Module#rpc_execute You should use Msf::RPC::RPC_Module#rpc_execute instead.
  # @param [Integer] sid Session ID.
  # @param [String] data Meterpreter script name.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('session.meterpreter_script', 3, 'checkvm')
  def rpc_meterpreter_script( sid, data)
    rpc_meterpreter_run_single( sid, "run #{data}")
  end

  # Changes the Transport of a given Meterpreter Session
  #
  # @param sid [Integer] The Session ID of the `Msf::Session`
  # @option opts [String] :transport The transport protocol to use (e.g. reverse_tcp, reverse_http, bind_tcp etc)
  # @option opts [String] :lhost  The LHOST of the listener to use
  # @option opts [String] :lport The LPORT of the listener to use
  # @option opts [String] :ua The User Agent String to use for reverse_http(s)
  # @option opts [String] :proxy_host The address of the proxy to route transport through
  # @option opts [String] :proxy_port The port the proxy is listening on
  # @option opts [String] :proxy_type The type of proxy to use
  # @option opts [String] :proxy_user The username to authenticate to the proxy with
  # @option opts [String] :proxy_pass The password to authenticate to the proxy with
  # @option opts [String] :comm_timeout Connection timeout in seconds
  # @option opts [String] :session_exp  Session Expiration Timeout
  # @option opts [String] :retry_total Total number of times to retry etsablishing the transport
  # @option opts [String] :retry_wait The number of seconds to wait between retries
  # @option opts [String] :cert  Path to the SSL Cert to use for HTTPS
  # @return [Boolean] whether the transport was changed successfully
  def rpc_meterpreter_transport_change(sid,opts={})
    session = _valid_session(sid,"meterpreter")
    real_opts = {}
    opts.each_pair do |key, value|
      real_opts[key.to_sym] = value
    end
    real_opts[:uuid] = session.payload_uuid
    result = session.core.transport_change(real_opts)
    if result == true
      rpc_stop(sid)
    end
    result
  end


  # Returns the separator used by the meterpreter.
  #
  # @param [Integer] sid Session ID.
  # @raise [Msf::RPC::Exception] An error that could be one of these:
  #                              * 500 Session ID is unknown.
  #                              * 500 Invalid session type.
  # @return [Hash] A hash that contains the separator. It contains the following key:
  #  * 'separator' [String] The separator used by the meterpreter.
  # @example Here's how you would use this from the client:
  #  # This returns:
  #  # {"separator"=>"\\"}
  #  rpc.call('session.meterpreter_directory_separator', 3)
  def rpc_meterpreter_directory_separator(sid)
    s = _valid_session(sid,"meterpreter")

    { "separator" => s.fs.file.separator }
  end


  # Returns all the compatible post modules for this session.
  #
  # @param [Integer] sid Session ID.
  # @return [Hash] Post modules. It contains the following key:
  #  * 'modules' [Array<string>] An array of post module names. Example: ['post/windows/wlan/wlan_profile']
  # @example Here's how you would use this from the client:
  #  rpc.call('session.compatible_modules', 3)
  def rpc_compatible_modules( sid)
    ret = []

    mtype = "post"
    names = self.framework.post.keys.map{ |x| "post/#{x}" }
    names.each do |mname|
      m = _find_module(mtype, mname)
      next if not m.session_compatible?(sid)
      ret << m.fullname
    end
    { "modules" => ret }
  end

private

  def _find_module(mtype,mname)
    mod = self.framework.modules.create(mname)
    if(not mod)
      error(500, "Invalid Module")
    end

    mod
  end

  def _valid_session(sid,type)

    s = self.framework.sessions[sid.to_i]

    if(not s)
      error(500, "Unknown Session ID #{sid}")
    end

    if type == "ring"
      if not s.respond_to?(:ring)
        error(500, "Session #{s.type} does not support ring operations")
      end
    elsif (type == 'meterpreter' && s.type != type) ||
      (type == 'shell' && s.type == 'meterpreter')
      error(500, "Session is not of type " + type)
    end
    s
  end

end
end
end

