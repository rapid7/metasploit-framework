module Msf
module Ui
module Console
module CommandDispatcher
class Evasion

  include Msf::Ui::Console::ModuleCommandDispatcher

  def commands
    super.update({
      'run'      => 'Launches the evasion module',
      'rerun'    => 'Reloads and launches the evasion module',
      'exploit'  => 'This is an alias for the run command',
      'rexploit' => 'This is an alias for the rerun command',
      'reload'   => 'Reloads the auxiliary module'
    }).merge(mod ? mod.evasion_commands : {})
  end

  def name
    'Evasion'
  end

  def cmd_run(*args)
    begin
      mod.run_simple(
          'LocalInput' => driver.input,
          'LocalOutput' => driver.output
        )
    rescue ::Interrupt
      print_error('Evasion interrupted by the console user')
    rescue ::Exception => e
      print_error("Evasion failed: #{e.class} #{e}")
    end
  end

  alias cmd_exploit cmd_run

  def cmd_rerun(*args)
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rexploit cmd_rerun

end
end
end
end
end