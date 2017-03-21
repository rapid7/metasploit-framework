##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/http'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Shodan Honeyscore Client',
      'Description' => %q{
        This module uses the shodan API to check
        if a server is a honeypot or not. The api
        returns a score from 0.0 to 1.0. 1.0 being a honeypot.
        A shodan API key is needed for this module to work properly.

        If you don't have an account, go here to register:
        https://account.shodan.io/register
      },
      'Author' =>
        [ 'thecarterb' ],
      'License' => MSF_LICENSE
      )
    )

    deregister_options('DOMAIN', 'DigestAuthIIS', 'NTLM::SendLM',
      'NTLM::SendNTLM', 'VHOST', 'RPORT', 'NTLM::SendSPN', 'NTLM::UseLMKey',
      'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2')

    register_options(
      [
        OptString.new('SHODAN_APIKEY', [true, 'The SHODAN API key'])
      ], self.class)
  end

  # Function to query the shodan API
  def honeypot_query(ip, key)

    print_status("Scanning #{rhost}")
    uri = URI("https://api.shodan.io/labs/honeyscore/#{ip}?key=#{key}")
    res = Net::HTTP.get(uri)

    score = res.to_f

    if score < 0.4
      print_error("#{rhost} is probably not a honeypot")
    elsif score > 0.4 & score < 0.6
      print_status("#{rhost} might be a honeypot")
    elsif score > 0.6 & score < 1.0
      print_good("#{rhost} is probably a honeypot")
    elsif score == 1.0
      print_good("#{rhost} is definitely a honeypot")
    else
      print_error("Got an unexpected response from shodan")
      print_raw("Response: #{res}")
      return
    end
    print_status("#{rhost} honeyscore: #{score}")
  end

  def run
    key = datastore['SHODAN_APIKEY']
    honeypot_query(rhost, key)
  end
end
