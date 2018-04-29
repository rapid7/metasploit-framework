##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/http'
require 'uri'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'GMail User Enumeration',
      'Description' => %q{
        Enumerate valid GMail email addresses.
      },
      'Author'      => ['x0rz', 'Mateus Lino <dctoralves[at]gmail.com>'],
      'References'  => [[ 'URL', 'https://blog.0day.rocks/abusing-gmail-to-get-previously-unlisted-e-mail-addresses-41544b62b2' ]],
      'License'     => MSF_LICENSE))
    register_options [ OptString.new('check_email', [ true, 'Email adddress to validate', 'example@gmail.com' ]) ]
    deregister_options 'RHOST', 'RPORT', 'VHOST'
  end

  def gmail_checker(email)
    print_status "Checking  #{email} ..."
    uri = URI.parse "https://mail.google.com/mail/gxlu?email=#{email}"
    http = Net::HTTP.new uri.host, uri.port
    http.use_ssl = true
    request = Net::HTTP::Get.new uri.request_uri
    res = http.request request
    return false if res.nil?
    cookies = res.get_fields 'set-cookie'
    return false if cookies.nil?
    cookies.each { |c| return true if c.include?('COMPASS=') }
  end

  def run
    print_status 'Enumerating email addresses...'
    email = datastore['check_email']
    print_status "#{email}@gmail.com: #{gmail_checker email}"
  end
end
