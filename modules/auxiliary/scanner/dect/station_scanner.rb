##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::DECT_COA

  def initialize
    super(
      'Name' => 'DECT Base Station Scanner',
      'Description' => 'This module scans for DECT base stations.',
      'Author' => [ 'DK <privilegedmode[at]gmail.com>' ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )
  end

  def print_results
    print_line("RFPI\t\tChannel")
    @base_stations.each_value do |data|
      print_line("#{data['rfpi']}\t#{data['channel']}")
    end
  end

  def run
    @base_stations = {}

    print_status("Opening interface: #{datastore['INTERFACE']}")
    print_status("Using band: #{datastore['BAND']}")

    open_coa

    begin
      print_status('Changing to fp scan mode.')
      fp_scan_mode
      print_status('Scanning...')

      loop do
        data = poll_coa

        if data
          parsed_data = parse_station(data)
          if !@base_stations.key?(parsed_data['rfpi'])
            print_good("Found New RFPI: #{parsed_data['rfpi']}")
            @base_stations[parsed_data['rfpi']] = parsed_data
          end
        end

        next_channel

        vprint_status("Switching to channel: #{channel}")
        select(nil, nil, nil, 1)
      end
    ensure
      print_status('Closing interface')
      stop_coa
      close_coa
    end

    print_results
  end
end
