##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Scanner
  include Msf::OptionalSession::MSSQL

  def initialize
    super(
      'Name' => 'MSSQL Version Utility',
      'Description' => 'Executes a TDS7 pre-login request against the MSSQL instance to query for version information, with enhanced RHOSTS handling.',
      'Author' => 'Zach Goldman',
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('RHOSTS', [true, 'Target IP address(es) (CIDR, range, space/comma-separated)', nil]),
      Opt::RPORT(1433)
    ])
  end

  def run
    # Parse RHOSTS to handle CIDR, ranges, spaces, and commas
    targets = parse_rhosts(datastore['RHOSTS'])
    if targets.empty?
      print_error('No valid targets found in RHOSTS')
      return
    end

    targets.each do |ip|
      begin
        print_status("Scanning #{ip}...")
        run_host(ip)
      rescue ::Rex::ConnectionError
        print_error("Failed to connect to #{ip}:#{datastore['RPORT']}")
      ensure
        disconnect
      end
    end
  end

  def run_host(ip)
    datastore['RHOSTS'] = ip  # Set the current target in the datastore for each iteration

    if session
      set_mssql_session(session.client)
      data = mssql_client.initial_connection_info[:prelogin_data]
    else
      create_mssql_client  # Uses the current datastore['RHOSTS'] and datastore['RPORT']
      data = mssql_prelogin
    end

    if data.blank?
      print_error("Unable to retrieve version information for #{ip}")
      return
    end

    print_status("SQL Server for #{ip}:")
    if data[:version]
      print_good("Version: #{data[:version]}")
    else
      print_error('Unknown Version')
    end
    if data[:encryption]
      case data[:encryption]
      when ENCRYPT_OFF
        data[:encryption] = 'off'
      when ENCRYPT_ON
        data[:encryption] = 'on'
      when ENCRYPT_NOT_SUP
        data[:encryption] = 'unsupported'
      when ENCRYPT_REQ
        data[:encryption] = 'required'
      else
        data[:encryption] = 'unknown'
      end
      print_good("Encryption: #{data[:encryption]}")
    else
      print_error('Unknown encryption status')
    end

    report_mssql_service(ip, data)
  end

  def parse_rhosts(input)
    # Parse RHOSTS to handle CIDR, spaces, commas, and ranges
    ips = []
    input.to_s.split(/[\s,]+/).each do |entry|
      begin
        if entry.include?('/')
          # Handle CIDR notation
          Rex::Socket::RangeWalker.new(entry).each { |ip| ips << ip }
        elsif entry.include?('-')
          # Handle IP ranges (e.g., 192.168.1.1-192.168.1.10)
          Rex::Socket::RangeWalker.new(entry).each { |ip| ips << ip }
        else
          # Handle single IPs
          ips << entry
        end
      rescue ArgumentError
        print_error("Invalid entry in RHOSTS: #{entry}")
      end
    end
    ips.uniq
  end
  

  def report_mssql_service(ip, data)
    mssql_info = 'Version: %<version>s, Encryption: %<encryption>s' % {
      version: data[:version] || 'unknown',
      encryption: data[:encryption] || 'unknown'
    }
    report_service(
      host: ip,
      port: datastore['RPORT'],
      name: 'mssql',
      info: mssql_info,
      state: data[:status] || 'closed'
    )
  end
end
