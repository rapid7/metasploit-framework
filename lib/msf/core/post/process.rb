# -*- coding: binary -*-

module Msf::Post::Process

  include Msf::Post::File

  def initialize(info = {})
    super(update_info(
      info,
      'Compat' => { 'Meterpreter' => { 'Commands' => %w{
        stdapi_sys_process_get_processes
        stdapi_sys_process_kill
      } } }
    ))
  end

  #
  # Gets the `pid`(s) of a specified program
  #
  def pidof(program)
    pids = []
    get_processes.each do |p|
       pids << p["pid"] if p['name'] =~ /(^|[\\\/])#{::Regexp.escape(program)}$/
    end
    pids
  end

  #
  # Checks if the remote system has a process with ID +pid+
  #
  def has_pid?(pid)
    pid_list = get_processes.collect { |e| e['pid'] }
    pid_list.include?(pid)
  end

  #
  # Gets the `pid` and `name` of the processes on the remote system
  #
  def get_processes
    if session.type == 'meterpreter'
      meterpreter_get_processes
    elsif session.type == 'powershell'
      shell_get_processes
    else
      shell_get_processes
    end
  end

  #
  # Forcefully terminate process with ID `pid` on the remote system
  #
  # @return [Boolean] True upon success
  #
  def kill_process(pid)
    if session.type == 'meterpreter' && session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_SYS_PROCESS_KILL)
      session.sys.process.kill(pid)
      return true
    end

    if session.platform == 'windows'
      return !cmd_exec("taskkill /F /PID #{pid}").to_s.starts_with?('ERROR')
    end

    cmd_exec("kill -9 #{pid} && echo true").to_s.include?('true')
  rescue Rex::Post::Meterpreter::RequestError
    false
  end

  def meterpreter_get_processes
    begin
      return session.sys.process.get_processes.map { |p| p.slice('name', 'pid') }
    rescue Rex::Post::Meterpreter::RequestError
      shell_get_processes
    end
  end

  def shell_get_processes
    processes = []
    if session.platform == 'windows'
      tasklist = cmd_exec('tasklist').split("\n")
      4.times { tasklist.delete_at(0) }
      tasklist.each do |p|
        properties = p.split
        process = {}
        process['name'] = properties[0]
        process['pid'] = properties[1].to_i
        processes.push(process)
      end
      # adding manually because this is common for all windows I think and splitting for this was causing problem for other processes.
      processes.prepend({ 'name' => '[System Process]', 'pid' => 0 })
    else
      if command_exists?('ps')
        ps_aux = cmd_exec('ps aux').split("\n")
        ps_aux.delete_at(0)
        ps_aux.each do |p|
          properties = p.split
          process = {}
          process['name'] = properties[10].gsub(/\[|\]/,"")
          process['pid'] = properties[1].to_i
          processes.push(process)
        end
      elsif directory?('/proc')
        directories_proc = dir('/proc/')
        directories_proc.each do |elem|
          elem.to_s.gsub(/ *\n+/, '')
          next unless elem[-1].match? /\d/

          process = {}
          process['pid'] = elem.to_i
          status = read_file("/proc/#{elem}/status") # will return nil if the process `elem` PID got vanished
          next unless status

          process['name'] = status.split(/\n|\t/)[1]
          processes.push(process)
        end
      else
        raise "Can't enumerate processes because `ps' command and `/proc' directory doesn't exist."
      end
    end
    return processes
  end

end
