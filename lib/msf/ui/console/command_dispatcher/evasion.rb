module Msf
module Ui
module Console
module CommandDispatcher
class Evasion

  include Msf::Ui::Console::ModuleCommandDispatcher

  def commands
    super.update({
      'run'        => 'Launches the evasion module',
      'rerun'      => 'Reloads and launches the evasion module',
      'exploit'    => 'This is an alias for the run command',
      'rexploit'   => 'This is an alias for the rerun command',
      'reload'     => 'Reloads the auxiliary module',
      'to_handler' => 'Creates a handler with the specified payload'
    }).merge(mod ? mod.evasion_commands : {})
  end

  def name
    'Evasion'
  end

  def cmd_run(*args)
    opts = {
      'Encoder'    => mod.datastore['ENCODER'],
      'Payload'    => mod.datastore['PAYLOAD'] || Evasion.choose_payload(mod),
      'Nop'        => mod.datastore['NOP'],
      'LocalInput' => driver.input,
      'LocalOutput' => driver.output
    }

    begin
      mod.run_simple(opts)
    rescue ::Interrupt
      print_error('Evasion interrupted by the console user')
    rescue ::Exception => e
      print_error("Evasion failed: #{e.class} #{e}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end
  end

  alias cmd_exploit cmd_run

  def cmd_rerun(*args)
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rexploit cmd_rerun

  def cmd_exploit_tabs(str, words)
    fmt = {
      '-e' => [ framework.encoders.map { |refname, mod| refname } ],
      '-f' => [ nil                                               ],
      '-h' => [ nil                                               ],
      '-j' => [ nil                                               ],
      '-J' => [ nil                                               ],
      '-n' => [ framework.nops.map { |refname, mod| refname }     ],
      '-o' => [ true                                              ],
      '-p' => [ framework.payloads.map { |refname, mod| refname } ],
      '-t' => [ true                                              ],
      '-z' => [ nil                                               ]
    }
    tab_complete_generic(fmt, str, words)
  end

  def cmd_to_handler(*_args)
    handler = framework.modules.create('exploit/multi/handler')

    handler_opts = {
      'Payload'        => mod.datastore['PAYLOAD'],
      'LocalInput'     => driver.input,
      'LocalOutput'    => driver.output,
      'ExitOnSession'  => false,
      'RunAsJob'       => true
    }

    handler.share_datastore(mod.datastore)
    handler.exploit_simple(handler_opts)
    job_id = handler.job_id

    print_status "Payload Handler Started as Job #{job_id}"
  end

  private

  def self.choose_payload(mod)

    # Choose either the real target or an invalid address
    # This is used to determine the LHOST value
    rhost = mod.datastore['RHOST'] || '50.50.50.50'

    # A list of preferred payloads in the best-first order
    pref = [
      'windows/meterpreter/reverse_https',
      'windows/meterpreter/reverse_tcp_rc4',
      'windows/meterpreter/reverse_tcp',
      'windows/x64/meterpreter/reverse_https',
      'windows/x64/meterpreter/reverse_tcp_rc4',
      'windows/x64/meterpreter/reverse_tcp',
      'linux/x86/meterpreter/reverse_tcp',
      'java/meterpreter/reverse_tcp',
      'php/meterpreter/reverse_tcp',
      'php/meterpreter_reverse_tcp',
      'ruby/shell_reverse_tcp',
      'nodejs/shell_reverse_tcp',
      'cmd/unix/interact',
      'cmd/unix/reverse',
      'cmd/unix/reverse_perl',
      'cmd/unix/reverse_netcat_gaping',
      'cmd/unix/reverse_stub',
      'cmd/unix/bind_stub',
      'windows/meterpreter/reverse_nonx_tcp',
      'windows/meterpreter/reverse_ord_tcp',
      'windows/shell/reverse_tcp',
      'generic/shell_reverse_tcp'
    ]
    pset = mod.compatible_payloads.map{|x| x[0] }
    pref.each do |n|
      if(pset.include?(n))
        mod.datastore['PAYLOAD'] = n
        if n.index('reverse')
          mod.datastore['LHOST'] = Rex::Socket.source_address(rhost)
        end
        return n
      end
    end

    return
  end

end
end
end
end
end
