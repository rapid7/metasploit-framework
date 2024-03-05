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
      'Description' => 'Executes a TDS7 pre-login request against the MSSQL instance to query for version information.',
      'Author' => 'Zach Goldman',
      'License' => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(1433)
    ])
  end

  def run
    if session
      set_mssql_session(session.client)
    else
      create_mssql_client
    end

    data = mssql_prelogin

    if data.nil? || data.empty?
      print_error("Unable to retrieve version information for #{mssql_client.address}")
      return
    end

    data[:status] = 'open' if data[:version] || data[:encryption]

    print_status("SQL Server for #{mssql_client.address}:")
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
      print_good("Encryption is #{data[:encryption]}")
    else
      print_error('Unknown encryption status')
    end

    report_mssql_service(mssql_client.address, data)
    mssql_client.disconnect
  end

  def report_mssql_service(ip, data)
    mssql_info = 'Version: %<version>s, Encryption: %<encryption>s' % [
      version: data[:version] || 'unknown',
      encryption: data[:encryption] || 'unknown'
    ]
    report_service(
      host: ip,
      port: mssql_client.port,
      name: 'mssql',
      info: mssql_info,
      state: (data['Status'].nil? ? 'closed' : data['Status'])
    )
  end
end
