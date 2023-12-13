##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'metasploit/framework/mssql/client'

class MetasploitModule < Msf::Auxiliary
  include Metasploit::Framework::MSSQL::Client

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server Generic Query from File',
      'Description'    => %q{
        This module will allow for multiple SQL queries contained within a specified
        file to be executed against a Microsoft SQL (MSSQL) Server instance, given
        the appropriate credentials.
      },
      'Author'         => [ 'j0hn__f : <jf[at]tinternet.org.uk>' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptPath.new('SQL_FILE', [ true, "File containing multiple SQL queries execute (one per line)"]),
        OptString.new('QUERY_PREFIX', [ false, "string to append each line of the file",""]),
        OptString.new('QUERY_SUFFIX', [ false, "string to prepend each line of the file",""]),
        Opt::RHOST,
        Opt::RPORT(1433),
        OptString.new('USERNAME', [ false, 'The username to authenticate as', 'sa']),
        OptString.new('PASSWORD', [ false, 'The password for the specified username', '']),
        OptBool.new('TDSENCRYPTION', [ true, 'Use TLS/SSL for TDS data "Force Encryption"', false]),
        OptBool.new('USE_WINDOWS_AUTHENT', [ true, 'Use windows authentication (requires DOMAIN option set)', false]),
      ])
  end


  def run
    set_sane_defaults
    queries = File.readlines(datastore['SQL_FILE'])

    prefix = datastore['QUERY_PREFIX']
    suffix = datastore['QUERY_SUFFIX']

    begin
      queries.each do |sql_query|
        vprint_status("Executing: #{sql_query}")
        mssql_query(prefix+sql_query.chomp+suffix,true) if mssql_login(datastore['USERNAME'], datastore['PASSWORD'])
      end
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout
      print_error "Error connecting to server: #{$!}"
    ensure
      disconnect
    end
  end
end
