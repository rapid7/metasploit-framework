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
      'Description' => 'This module simply queries the MSSQL instance for version information.',
      'Author' => 'MC',
      'License' => MSF_LICENSE
    )
  end

  def run
    if session
      set_session(session.client)
    end
    version = mssql_get_version
    if version && !version.empty?
      print_status("SQL Server for #{mssql_client.address}:")
      print_good("Version: #{version}")
    end
  end
end
