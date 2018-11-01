##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'          =>  'iOS Text Gatherer',
      'Description'   =>  %q{
        This module collects images and text messages from iPhones.
      },
      'License'       =>  MSF_LICENSE,
      'Author'        =>  [ 'Shelby Pace' ], # Metasploit Module
      'Platform'      =>  [ 'apple_ios' ],
      'SessionTypes'  =>  [ 'meterpreter' ]
    ))
  end

  def run

  end
end
