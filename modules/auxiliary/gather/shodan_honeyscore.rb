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
        For more info on how their honeyscore system works, go here:
        https://honeyscore.shodan.io/
      },
      'Author'  => [ 'thecarterb' ],
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

  def print_score(score)
    print_status("#{rhost} honeyscore: #{score}")
  end

  # Function to query the shodan API
  def honeypot_query(ip, key)

    print_status("Scanning #{rhost}")
    uri = URI("https://api.shodan.io/labs/honeyscore/#{ip}?key=#{key}")
    res = Net::HTTP.get(uri)
    score = res.to_f

    if res.to_s.include? "Unauthorized"
      print_error('Shodan did not respond in an expected way. Check your api key')
      return
    end

    if score < 0.4
      print_error("#{rhost} is probably not a honeypot")
      print_score(score)
    elsif score > 0.4 && score < 0.6
      print_status("#{rhost} might be a honeypot")
      print_score(score)
    elsif score > 0.6 && score < 1.0
      print_good("#{rhost} is probably a honeypot")
      print_score(score)
    elsif score == 1.0
      print_good("#{rhost} is definitely a honeypot")
      print_score(score)
    else  # We shouldn't ever get here as the previous check should catch an unexpected response
      print_error('An unexpected error occured.')
      return
    end
  end

  def run
    key = datastore['SHODAN_APIKEY']
    honeypot_query(rhost, key)
  end
end
