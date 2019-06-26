##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/powershell'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Powershell Execution Post Module",
      'Description'          => %q{
        This module will execute a powershell script in a meterpreter session.
        The user may also enter text substitutions to be made in memory before execution.
        Setting VERBOSE to true will output both the script prior to execution and the results.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['windows'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => [
        'Nicholas Nam (nick[at]executionflow.org)', # original meterpreter script
        'RageLtMan <rageltman[at]sempervictus>' # post module and libs
        ]
    ))

    register_options(
      [
        OptString.new( 'SCRIPT',  [true, 'Path to the local PS script or command string to execute']),
      ])

    register_advanced_options(
      [
        OptString.new('SUBSTITUTIONS', [false, 'Script subs in gsub format - original,sub;original,sub']),
      ])

  end

  def run

    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    raise "Powershell not available" if ! have_powershell?

    # Preprocess the Powershell::Script object with substitions from Exploit::Powershell
    script = make_subs(read_script(datastore['SCRIPT']), process_subs(datastore['SUBSTITUTIONS']))

    # Execute in session
    print_status psh_exec(script)
    print_good 'Finished!'
  end
end
