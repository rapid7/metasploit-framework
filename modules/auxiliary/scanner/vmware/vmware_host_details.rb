##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'VMWare Enumerate Host Details',
      'Description'    => %Q{
        This module attempts to enumerate information about the host systems through the VMWare web API.
        This can include information about the hardware installed on the host machine.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
        OptBool.new('HW_DETAILS', [true, "Enumerate the Hardware on the system as well?", false])
      ], self.class)

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end

  def run_host(ip)

    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      output = "VMWare Host at #{ip} details\n"
      output << "-----------------------------\n"
      host_summary = vim_get_all_host_summary(datastore['HW_DETAILS'])
      output << YAML.dump(host_summary)
      print_good output

      f = store_loot('vmware_host_details', "text/plain", datastore['RHOST'], output, "#{datastore['RHOST']}_vmware_host.txt", "VMWare Host Details")
      vprint_status("Host details stored in: #{f}")
    else
      print_error "Login Failure on #{ip}"
      return
    end
  end

end
