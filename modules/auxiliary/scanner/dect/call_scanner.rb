##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::DECT_COA

  def initialize
    super(
      'Name'           => 'DECT Call Scanner',
      'Description'    => 'This module scans for active DECT calls',
      'Author'         => [ 'DK <privilegedmode[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    )
  end

  def print_results
    print_line("Time\t\t\t\tRFPI\t\tChannel")
    @calls.each do |rfpi, data|
      print_line("#{data['time']}\t#{data['rfpi']}\t#{data['channel']}")
    end
  end


=begin
  def record_call(data)
    print_status("Synchronizing..")
    pp_scan_mode(data['rfpi_raw'])
    while(true)
      data = poll_coa()
      puts data
    end
  end
=end

  def run
    @calls = {}

    print_status("Opening interface: #{datastore['INTERFACE']}")
    print_status("Using band: #{datastore['BAND']}")

    open_coa

    begin

      print_status("Changing to call scan mode.")
      call_scan_mode
      print_status("Scanning...")

      while (true)
        data = poll_coa()
        if (data)
          parsed_data = parse_call(data)
          parsed_data['time'] = Time.now
          print_good("Found active call on: #{parsed_data['rfpi']}")
          @calls[parsed_data['time']] = parsed_data
        end

        next_channel

        vprint_status("Switching to channel: #{channel}")
        select(nil,nil,nil,1)
      end
    ensure
      print_status("Closing interface")
      stop_coa()
      close_coa()
    end

    print_results
  end
end
