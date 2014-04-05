# -*- coding: binary -*-
require 'rex'
require 'rex/ui/text/output/buffer'

module Msf
module RPC
class RPC_Session < RPC_Base

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
        'routes'       => s.routes.join(",")
      }
      if(s.type.to_s == "meterpreter")
        res[s.sid]['platform'] = s.platform.to_s
      end
    end
    res
  end

  def rpc_stop( sid)

    s = self.framework.sessions[sid.to_i]
    if(not s)
      error(500, "Unknown Session ID")
    end
    s.kill rescue nil
    { "result" => "success" }
  end

  # Shell read is now a positon-aware reader of the shell's associated
  # ring buffer. For more direct control of the pointer into a ring
  # buffer, a client can instead use ring_read, and note the returned
  # sequence number on their own (making multiple views into the same
  # session possible, regardless of position in the stream)
  def rpc_shell_read( sid, ptr=nil)
    _valid_session(sid,"shell")
    # @session_sequence tracks the pointer into the ring buffer
    # data of sessions (by sid) in order to emulate the old behavior
    # of shell_read
    @session_sequence ||= {}
    @session_sequence[sid] ||= 0
    ring_buffer = rpc_ring_read(sid,(ptr || @session_sequence[sid]))
    if not (ring_buffer["seq"].nil? || ring_buffer["seq"].empty?)
      @session_sequence[sid] = ring_buffer["seq"].to_i
    end
    return ring_buffer
  end

  # shell_write is pretty much totally identical to ring_put
  def rpc_shell_write( sid, data)
    _valid_session(sid,"shell")
    rpc_ring_put(sid,data)
  end

  def rpc_shell_upgrade( sid, lhost, lport)
    s = _valid_session(sid,"shell")
    s.exploit_datastore['LHOST'] = lhost
    s.exploit_datastore['LPORT'] = lport
    s.execute_script('spawn_meterpreter', nil)
    { "result" => "success" }
  end

  def rpc_meterpreter_read( sid)
    s = _valid_session(sid,"meterpreter")

    if not s.user_output.respond_to? :dump_buffer
      s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
    end

    data = s.user_output.dump_buffer
    { "data" => data }
  end

  def rpc_ring_read( sid, ptr=nil)
    s = _valid_session(sid,"ring")
    begin
      res = s.ring.read_data(ptr)
      { "seq" => res[0].to_s, "data" => res[1].to_s }
    rescue ::Exception => e
      error(500, "Session Disconnected: #{e.class} #{e}")
    end
  end

  def rpc_ring_put( sid, data)
    s = _valid_session(sid,"ring")
    begin
      res = s.shell_write(data)
      { "write_count" => res.to_s}
    rescue ::Exception => e
      error(500, "Session Disconnected: #{e.class} #{e}")
    end
  end

  def rpc_ring_last( sid)
    s = _valid_session(sid,"ring")
    { "seq" => s.ring.last_sequence.to_s }
  end

  def rpc_ring_clear( sid)
    s = _valid_session(sid,"ring")
    res = s.ring.clear_data
    if res.compact.empty?
      { "result" => "success"}
    else # Doesn't seem like this can fail. Maybe a race?
      { "result" => "failure"}
    end
  end

  #
  # Run a single meterpreter console command
  #
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

  def rpc_meterpreter_tabs(sid, line)
    s = _valid_session(sid,"meterpreter")
    { "tabs" => s.console.tab_complete(line) }
  end

  # runs a meterpreter command even if interacting with a shell or other channel
  def rpc_meterpreter_run_single( sid, data)
    s = _valid_session(sid,"meterpreter")

    if not s.user_output.respond_to? :dump_buffer
      s.init_ui(Rex::Ui::Text::Input::Buffer.new, Rex::Ui::Text::Output::Buffer.new)
    end

    self.framework.threads.spawn("MeterpreterRunSingle", false, s) { |sess| sess.console.run_single(data) }
    { "result" => "success" }
  end

  def rpc_meterpreter_script( sid, data)
    rpc_meterpreter_run_single( sid, "run #{data}")
  end

  def rpc_meterpreter_directory_separator(sid)
    s = _valid_session(sid,"meterpreter")

    { "separator" => s.fs.file.separator }
  end

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
      error(500, "Unknown Session ID")
    end

    if type == "ring"
      if not s.respond_to?(:ring)
        error(500, "Session #{s.type} does not support ring operations")
      end
    elsif (s.type != type)
      error(500, "Session is not of type " + type)
    end
    s
  end

end
end
end

