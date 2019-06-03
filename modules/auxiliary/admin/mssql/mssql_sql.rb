##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL

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
    mssql_query(datastore['SQL'], true) if mssql_login_datastore
    disconnect
  end
end
