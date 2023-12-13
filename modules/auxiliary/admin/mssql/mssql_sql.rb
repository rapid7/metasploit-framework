##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'metasploit/framework/mssql/client'

class MetasploitModule < Msf::Auxiliary
  include Metasploit::Framework::MSSQL::Client

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server Generic Query',
      'Description'    => %q{
          This module will allow for simple SQL statements to be executed against a
          MSSQL/MSDE instance given the appropriate credentials.
      },
      'Author'         => [ 'tebo <tebo[at]attackresearch.com>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.attackresearch.com' ],
          [ 'URL', 'http://msdn.microsoft.com/en-us/library/cc448435(PROT.10).aspx'],
        ]
    ))

    register_options(
      [
        OptString.new('SQL', [ false, 'The SQL query to execute',  'select @@version']),
        Opt::RHOST,
        Opt::RPORT(1433),
        OptString.new('USERNAME', [ false, 'The username to authenticate as', 'sa']),
        OptString.new('PASSWORD', [ false, 'The password for the specified username', '']),
        OptBool.new('TDSENCRYPTION', [ true, 'Use TLS/SSL for TDS data "Force Encryption"', false]),
        OptBool.new('USE_WINDOWS_AUTHENT', [ true, 'Use windows authentication (requires DOMAIN option set)', false]),
      ])
  end

  def auxiliary_commands
    { "select" => "Run a select query (a LIMIT clause is probably a really good idea)" }
  end

  def cmd_select(*args)
    datastore["SQL"] = "select #{args.join(" ")}"
    run
  end

  def run
    set_sane_defaults
    mssql_query(datastore['SQL'], true) if mssql_login_datastore
    disconnect
  end
end
