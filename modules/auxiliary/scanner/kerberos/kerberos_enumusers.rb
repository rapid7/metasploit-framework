##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Kerberos Domain User Enumeration',
      'Description' => %q{
        This module will enumerate valid Domain Users via Kerberos from an unauthenticated perspective. It utilises
        the different responses returned by the service for valid and invalid users.
      },
      'Author' =>
        [
          'Matt Byrne <attackdebris[at]gmail.com>' # Metasploit module
        ],
      'References' =>
        [
          [ 'URL', 'https://nmap.org/nsedoc/scripts/krb5-enum-users.html'],
        ],
      'License' => MSF_LICENSE,
    ))

    register_options(
      [
        OptString.new('DOMAIN', [ true, 'The Domain Eg: demo.local' ]),
        OptPath.new(
          'USER_FILE',
      [true, 'Files containing usernames, one per line', nil])
      ], self.class)
  end
  def user_list
    users = nil
    if File.readable? datastore['USER_FILE']
      users = File.new(datastore['USER_FILE']).read.split
      users.each {|u| u.downcase!}
      users.uniq!
    else
      raise ArgumentError, "Cannot read file #{datastore['USER_FILE']}"
  end
    users
  end
  def run
    print_status("Validating options...")

    domain = datastore['DOMAIN'].upcase
    user_file = datastore['USER_FILE']

    print_status("Using domain: #{domain}...")

    pre_auth = []
    pre_auth << build_pa_pac_request
    pre_auth

    user_list.each do |user|
      print_status("#{peer} - Testing User: \"#{user}\"...")
      res = send_request_as(
        client_name: "#{user}",
        server_name: "krbtgt/#{domain}",
        realm: "#{domain}",
        pa_data: pre_auth
    )
    print_status("#{peer} - #{warn_error(res)}") if res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
    test = Rex::Proto::Kerberos::Model::ERROR_CODES[res.error_code]
    if test == ["KDC_ERR_PREAUTH_REQUIRED", "Additional pre-authentication required"]
      print_good("#{peer} - User: \"#{user}\" is present")
    elsif test == ["KDC_ERR_CLIENT_REVOKED", "Clients credentials have been revoked"]
      print_error("#{peer} - User: \"#{user}\" account disabled or locked out")
    else
      print_status("#{peer} - User: \"#{user}\" does not exist")
    end
  end
  end

  def warn_error(res)
    msg = ''

    if Rex::Proto::Kerberos::Model::ERROR_CODES.has_key?(res.error_code)
      error_info = Rex::Proto::Kerberos::Model::ERROR_CODES[res.error_code]
      msg = "#{error_info[0]} - #{error_info[1]}"
    else
      msg = 'Wrong DOMAIN Name? Check DOMAIN and retry...'
    end
  end
end
