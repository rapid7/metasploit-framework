##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report


  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'WinRM Authentication Method Detection',
      'Description'    => %q{
        This module sends a request to an HTTP/HTTPS service to see if it is a WinRM service.
        If it is a WinRM service, it also gathers the Authentication Methods supported.
        },
      'Author'         => [ 'thelightcosine' ],
      'License'        => MSF_LICENSE
    )

    deregister_options('USERNAME', 'PASSWORD')

  end


  def run_host(ip)
    resp = winrm_poke
    return nil if resp.nil?
    if  resp.code == 401 and resp.headers['Server'] and resp.headers['Server'].include? "Microsoft-HTTPAPI"
      methods = parse_auth_methods(resp)
      desc = resp.headers['Server'] + " Authentication Methods: " + methods.to_s
      report_service(
        :host  => ip,
        :port  => rport,
        :proto => 'tcp',
        :name  => 'winrm',
        :info  => desc
      )
      print_good "#{ip}:#{rport}: Negotiate protocol supported" if methods.include? "Negotiate"
      print_good "#{ip}:#{rport}: Kerberos protocol supported" if methods.include? "Kerberos"
      print_good "#{ip}:#{rport}: Basic protocol supported" if methods.include? "Basic"
    else
      print_error "#{ip}:#{rport} Does not appear to be a WinRM server"
    end
  end


end
