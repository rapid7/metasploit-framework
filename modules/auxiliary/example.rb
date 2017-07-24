##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This sample auxiliary module simply displays the selected action and
# registers a custom command that will show up when the module is used.
#
###
class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Sample Auxiliary Module',
        # The description can be multiple lines, but does not preserve formatting.
        'Description' => 'Sample Auxiliary Module',
        'Author'      => ['Joe Module <joem@example.com>'],
        'License'     => MSF_LICENSE,
        'Actions'     => [
          [ 'Default Action' ],
          [ 'Another Action' ]
        ]
      )
    )
  end

  def run
    print_status("Running the simple auxiliary module with action #{action.name}")
  end

  # auxiliary modules can register new commands, they all call cmd_* to
  # dispatch them
  def auxiliary_commands
    { "aux_extra_command" => "Run this auxiliary test commmand" }
  end

  def cmd_aux_extra_command(*args)
    print_status("Running inside aux_extra_command(#{args.join(' ')})")
  end
end
