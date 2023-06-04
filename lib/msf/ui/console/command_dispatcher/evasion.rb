module Msf
module Ui
module Console
module CommandDispatcher
class Evasion

  include Msf::Ui::Console::ModuleCommandDispatcher
  include Msf::Ui::Console::ModuleOptionTabCompletion

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
      'Payload'    => mod.datastore['PAYLOAD'],
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
      elog('Evasion Failed', error: e)
    end
  end

  alias cmd_exploit cmd_run

  def cmd_rerun(*args)
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rexploit cmd_rerun

  #
  # Tab completion for the run command
  #
  def cmd_run_tabs(str, words)
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
    flags = tab_complete_generic(fmt, str, words)
    options = tab_complete_option(active_module, str, words)
    flags + options
  end

  #
  # Tab completion for the exploit command
  #
  alias cmd_exploit_tabs cmd_run_tabs

  def cmd_to_handler(*_args)
    handler = framework.modules.create('exploit/multi/handler')

    handler_opts = {
      'Payload'     => mod.datastore['PAYLOAD'],
      'LocalInput'  => driver.input,
      'LocalOutput' => driver.output,
      'RunAsJob'    => true,
      'Options'     => {
        'ExitOnSession' => false,
      }
    }

    handler.share_datastore(mod.datastore)

    replicant_handler = nil
    handler.exploit_simple(handler_opts) do |yielded_replicant_handler|
      replicant_handler = yielded_replicant_handler
    end

    if replicant_handler.nil?
      print_error('Failed to run module')
      return
    end

    if replicant_handler.error.nil?
      job_id = handler.job_id

      print_status "Payload Handler Started as Job #{job_id}"
    end
  end
end
end
end
end
end
