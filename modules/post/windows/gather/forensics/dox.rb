##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'csv'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/post/osx/system'




class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  include Msf::Post::OSX::System



  def initialize(info={})
    super( update_info( info,
        'Name' => 'dox [more info to come]',
        'Description' => %q{'Enter awesome description here.'},
        'License' => MSF_LICENSE,
        'Author' => [ 'Joshua Harper, Chief Cyber Warrior, Radix Forensics LLC (@JonValt) <josh at radixtx dot com>'],
        'Platform' => %w{ osx win },
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      ))
    register_advanced_options(
      [
        # Set as an advanced option since it can only be useful in shell sessions.
        OptInt.new('TIMEOUT', [true ,'Timeout in seconds when downloading file on a shell session.', 90]),
      ], self.class)
  end
 
  #Generic Ruby Stuff for my personal reference
  class Animals
    attr_accessor :name, :age, :trait
  end
def run
  print_status("Hello from Metasploit!")
end
end
