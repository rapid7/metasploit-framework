##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Capture

  def initialize
    super(
      'Name' => 'Pcap Replay Utility',
      'Description' => %q{
        Replay a packet capture (PCAP) file.
      },
      'Author' => 'amaloteaux',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [SERVICE_RESOURCE_LOSS],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )

    register_options([
      OptPath.new('FILENAME', [true, 'The local pcap file to process']),
      OptString.new('FILE_FILTER', [false, 'The filter string to apply on the file']),
      OptInt.new('LOOP', [true, 'The number of times to loop through the file', 1]),
      OptInt.new('DELAY', [true, 'the delay in millisecond between each loop', 0]),
      OptInt.new('PKT_DELAY', [true, 'the delay in millisecond between each packet', 0]),
    ])

    deregister_options('SNAPLEN', 'FILTER', 'PCAPFILE', 'RHOST', 'TIMEOUT', 'SECRET', 'GATEWAY_PROBE_HOST', 'GATEWAY_PROBE_PORT')
  end

  def run
    filename = datastore['FILENAME']

    unless File.exist?(filename) && File.file?(filename)
      print_error('Pcap File does not exist')
      return
    end

    check_pcaprub_loaded

    open_pcap

    vprint_status('Sending file...')

    pkt_delay = datastore['PKT_DELAY']
    delay = datastore['DELAY']
    iterations = datastore['LOOP']
    infinity = true if iterations <= 0
    file_filter = datastore['FILE_FILTER']
    count = 0
    while (iterations > 0) || infinity
      vprint_status("Sending file (iterations: #{count += 1})")
      inject_pcap(filename, file_filter, pkt_delay)
      iterations -= 1 unless infinity
      Kernel.select(nil, nil, nil, (delay * 1.0) / 1000) if (iterations > 0) || infinity
    end

    close_pcap
  end
end
