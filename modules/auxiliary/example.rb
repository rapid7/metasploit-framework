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
        'Name' => 'Sample Auxiliary Module',
        # The description can be multiple lines, but does not preserve formatting.
        'Description' => 'Sample Auxiliary Module',
        'Author' => ['Joe Module <joem@example.com>'],
        'License' => MSF_LICENSE,
        'Actions' => [
          [ 'Default Action', { 'Description' => 'This does something' } ],
          [ 'Another Action', { 'Description' => 'This does a different thing' } ]
        ],
        # The action(s) that will run as background job
        'PassiveActions' => [
          'Another Action'
        ],
        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'DefaultAction' => 'Default Action'
      )
    )
  end

  def run
    print_status("Running the simple auxiliary module with action #{action.name}")
  end

  # Framework automatically registers `cmd_*` methods to be dispatched when the
  # corresponding command is used. For example, here this method will be called
  # when entering the `aux_extra_command` command in the console.
  def cmd_aux_extra_command(*args)
    print_status("Running inside aux_extra_command(#{args.join(' ')})")
  end
end
