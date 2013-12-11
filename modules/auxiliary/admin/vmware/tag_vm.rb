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
      'Name'           => 'VMWare Tag Virtual Machine',
      'Description'    => %Q{
        This module will log into the Web API of VMWare and
        'tag' a specified Virtual Machine. It does this by
        logging a user event with user supplied text
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
        OptString.new('VM', [true, "The VM to try to Power On"]),
        OptString.new('MSG', [true, "The message to put in the log", 'Pwned by Metasploit'])
      ], self.class)

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end

  def run

    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      vm_ref = vim_find_vm_by_name(datastore['VM'])
      case vm_ref
      when String
        result = vim_log_event_vm(vm_ref, datastore['MSG'])
        case result
        when :noresponse
          print_error "Recieved no Response"
        when :expired
          print_error "The login session appears to have expired"
        when :error
          print_error "An error occured"
        else
          print_good "User Event logged"
        end
      when :noresponse
        print_error "Recieved no Response"
      when :expired
        print_error "The login session appears to have expired"
      when :error
        print_error @vim_soap_error
      end
    else
      print_error "Login Failure on #{datastore['RHOST']}"
      return
    end
  end

end
