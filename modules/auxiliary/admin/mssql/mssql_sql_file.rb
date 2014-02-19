##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MSSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server Generic Query from File',
      'Description'    => %q{
        This module will allow for multiple SQL queries contained within a specified
        file to be executed against a Microsoft SQL (MSSQL) Server instance, given
        the appropiate credentials.
      },
      'Author'         => [ 'j0hn__f : <jf[at]tinternet.org.uk>' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptPath.new('SQL_FILE', [ true, "File containing multiple SQL queries execute (one per line)"]),
        OptString.new('QUERY_PREFIX', [ false, "string to append each line of the file",""]),
        OptString.new('QUERY_SUFFIX', [ false, "string to prepend each line of the file",""])
      ], self.class)
  end


  def run
    queries = File.readlines(datastore['SQL_FILE'])

    prefix = datastore['QUERY_PREFIX']
    suffix = datastore['QUERY_SUFFIX']

    begin
      queries.each do |sql_query|
        vprint_status("Executing: #{sql_query}")
        mssql_query(prefix+sql_query.chomp+suffix,true) if mssql_login_datastore
      end
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout
      print_error "Error connecting to server: #{$!}"
    ensure
      disconnect
    end
  end
end
