##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap

  def initialize
    super(
      'Name'           => 'VMWare Power On Virtual Machine',
      'Description'    => %Q{
        This module will log into the Web API of VMWare and try to power on
        a specified Virtual Machine.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
        OptString.new('VM', [true, "The VM to try to Power On"])
      ], self.class)

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end

  def run

    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      vm_ref = vim_find_vm_by_name(datastore['VM'])
      case vm_ref
      when String
        return_state = vim_powerON_vm(vm_ref)
        case return_state
        when 'success'
          print_good "VM Powered On Successfully"
        when 'alreadyON'
          print_status "The Server says that VM #{datastore['VM']} is already on."
        else
          print_error "The server returned an unexpected status #{return_state}"
        end
      when :noresponse
        print_error "The request timed out"
      when :error
        print_error @vim_soap_error
      when nil
        print_error "Could not locate VM #{datastore['VM']}"
      end
    else
      print_error "Login Failure on #{datastore['RHOST']}"
      return
    end
  end

end
