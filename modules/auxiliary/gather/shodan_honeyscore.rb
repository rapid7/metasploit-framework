##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

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
      'Author' =>
        [ 'thecarterb' ],
      'License' => MSF_LICENSE
      )
    )

    deregister_options('RHOST', 'SSL', 'DOMAIN', 'DigestAuthIIS', 'NTLM::SendLM',
      'NTLM::SendNTLM', 'VHOST', 'RPORT', 'NTLM::SendSPN', 'NTLM::UseLMKey',
      'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2')

    register_options(
      [
        OptString.new('TARGET', [true, 'The target to get the score of']),
        OptString.new('SHODAN_APIKEY', [true, 'The SHODAN API key'])
      ], self.class)
  end

  def print_score(score)
    tgt = datastore['TARGET']
    print_status("#{tgt} honeyscore: #{score}")
  end

  def run
    key = datastore['SHODAN_APIKEY']
    tgt = datastore['TARGET']
    print_status("Scanning #{tgt}")
    cli = Rex::Proto::Http::Client.new('api.shodan.io', 443, {}, true)
    cli.connect
    req = cli.request_cgi({
      'uri'    => "/labs/honeyscore/#{tgt}?key=#{key}",
      'method' => 'GET'
      })
    res = cli.send_recv(req)
    cli.close
    if res.nil?
      fail_with(Failure::Unknown, 'Unable to connect to shodan')
    end

    if res.code != 200
      print_error('Shodan did not respond in an expected way. Check your api key')
      return
    end

    score = res.to_s.to_f  # Change the score to a float to be able to determine value in the checks

    if score == 0
      print_error("#{tgt} is not a honeypot")
      print_score(score)
    elsif score < 0.4 && score != 0.0
      print_error("#{tgt} is probably not a honeypot")
      print_score(score)
    elsif score > 0.4 && score < 0.6
      print_status("#{tgt} might be a honeypot")
      print_score(score)
    elsif score > 0.6 && score < 1.0
      print_good("#{tgt} is probably a honeypot")
      print_score(score)
    elsif score == 1.0
      print_good("#{tgt} is definitely a honeypot")
      print_score(score)
    else  # We shouldn't ever get here as the previous check should catch an unexpected response
      print_error('An unexpected error occured.')
      return
    end
  end
end
