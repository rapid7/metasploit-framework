##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Capture

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Pcap Replay Utility',
            'Description' => %q{
              Replay a pcap capture file
            },
            'Author'      => 'amaloteaux',
            'License'     => MSF_LICENSE
        )
    )

    register_options([
      OptPath.new('FILENAME', [true, "The local pcap file to process"]),
      OptString.new('FILE_FILTER', [false, "The filter string to apply on the file"]),
      OptInt.new('LOOP', [true, "The number of times to loop through the file",1]),
      OptInt.new('DELAY', [true, "the delay in millisecond between each loop",0]),
      OptInt.new('PKT_DELAY', [true, "the delay in millisecond between each packet",0]),
    ], self.class)

    deregister_options('SNAPLEN','FILTER','PCAPFILE','RHOST','TIMEOUT','UDP_SECRET','GATEWAY','NETMASK')
  end

  def run
    check_pcaprub_loaded # Check first
    pkt_delay = datastore['PKT_DELAY']
    delay = datastore['DELAY']
    loop = datastore['LOOP']
    infinity = true if loop <= 0
    file_filter = datastore['FILE_FILTER']
    filename = datastore['FILENAME']
    verbose = datastore['VERBOSE']
    count = 0
    unless File.exists? filename and File.file? filename
      print_error("Pcap File does not exist")
      return
    end
    open_pcap
    print_status("Sending file...") unless verbose
    while (loop > 0 or infinity) do
      vprint_status("Sending file (loop : #{count = count + 1})")
      inject_pcap(filename, file_filter, pkt_delay )
      loop -= 1 unless infinity
      Kernel.select(nil, nil, nil, (delay * 1.0)/1000) if loop > 0 or infinity
    end
    close_pcap
  end

end
