##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Exploit::Deprecated
  moved_from 'post/windows/gather/reverse_lookup'
  moved_from 'post/windows/recon/resolve_ip'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Reverse Lookup IP Addresses',
        'Description' => %q{
          This module reverse resolves an IP address or IP address range to hostnames.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'mubix' ],
        'Platform' => %w[win unix linux osx solaris bsd],
        'SessionTypes' => %w[meterpreter powershell shell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_railgun_memread
            ]
          }
        }
      )
    )
    register_options([
      OptAddress.new('ADDRESS', [ false, 'IP address to resolve']),
      OptAddressRange.new('RANGE', [ false, 'IP address range to resolve'])
    ])
  end

  def resolve_ip(ip)
    return unless Rex::Socket.dotted_ip?(ip)

    session.platform == 'windows' ? win_resolve_ip(ip) : unix_resolve_ip(ip)
  end

  def unix_resolve_ip(ip)
    return unless Rex::Socket.dotted_ip?(ip)

    res = cmd_exec("host #{ip}")

    return if res.blank?

    hostname = res.split("\n").first.split(' ').last

    if hostname.blank? || !hostname.ends_with?('.')
      print_error("Failed to resolve #{ip}")
      return
    end

    hostname.chomp('.')
  end

  def win_resolve_ip(ip)
    return unless Rex::Socket.dotted_ip?(ip)

    case session.type
    when 'powershell'
      host = cmd_exec("[System.Net.Dns]::GetHostEntry('#{ip}').HostName").to_s

      if host.blank?
        print_error("Failed to resolve #{ip}")
        return
      end

      return host
    when 'meterpreter'
      ip_ino = Rex::Socket.addr_aton(ip)

      result = client.railgun.ws2_32.gethostbyaddr(ip_ino, ip_ino.size, 2)

      if result.blank? || result['return'] == 0
        print_error("Failed to resolve #{ip}")
        return
      end

      memtext = client.railgun.memread(result['return'], 255)

      unless memtext.include?(ip_ino)
        print_error("Failed to resolve #{ip}")
        return
      end

      host = memtext.split(ip_ino)[1].split("\00")[0]

      if host.blank?
        print_error("Failed to resolve #{ip}")
        return
      end

      return host
    else
      fail_with(Failure::BadConfig, "Unsupported sesssion type #{session.type}")
    end
  rescue Rex::Post::Meterpreter::RequestError, Errno::ETIMEDOUT
    print_error("Failed to resolve #{ip}")
    nil
  end

  def run
    address = datastore['ADDRESS']
    range = datastore['RANGE']

    fail_with(Failure::BadConfig, 'ADDRESS or RANGE option must be set.') if address.blank? && range.blank?

    if session.platform == 'windows'
      if session.type == 'meterpreter'
        # Add ws2_32 just in case it isn't there...
        session.railgun.ws2_32

        # Check if gethostbyaddr is available
        modhandle = session.railgun.kernel32.GetModuleHandleA('ws2_32.dll')
        if modhandle['return'] == 0
          fail_with(Failure::Unknown, 'WS2_32 is not available at this time, exiting')
        end

        procaddr = session.railgun.kernel32.GetProcAddress(modhandle['return'], 'gethostbyaddr')
        if procaddr['return'] == 0
          fail_with(Failure::Unknown, 'WS2_32 was loaded but does not have the gethostbyaddr function, exiting')
        end
      end
    else
      fail_with(Failure::NoTarget, "`host' command not found") unless command_exists?('host')
    end

    unless address.blank?
      print_status("Resolving #{address}")
      host = resolve_ip(address)
      print_good("#{address} resolves to #{host}") unless host.blank?
    end

    unless range.blank?
      rex_range = Rex::Socket::RangeWalker.new(range)
      print_status("Resolving #{range} (#{rex_range.num_ips} hosts)")
      rex_range.each do |ip|
        host = resolve_ip(ip)
        print_good("#{ip} resolves to #{host}") unless host.blank?
      end
    end
  end
end
