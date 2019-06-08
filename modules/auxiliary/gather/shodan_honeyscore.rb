##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

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
        [ 'thecarterb' ],  # Thanks to @rwhitcroft, @h00die and @wvu-r7 for the improvements and review!
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'https://honeyscore.shodan.io/']
        ]
      )
    )

    register_options(
      [
        OptString.new('TARGET', [true, 'The target to get the score of']),
        OptString.new('SHODAN_APIKEY', [true, 'The SHODAN API key'])
      ])
  end

  def print_score(score)
    tgt = datastore['TARGET']
    print_status("#{tgt} honeyscore: #{score}/1.0")
  end

  def run
    key = datastore['SHODAN_APIKEY']

    # Check the length of the key (should be 32 chars)
    if key.length != 32
      print_error('Invalid API key (Not long enough)')
      return
    end

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

    score = res.body.to_f  # Change the score to a float to be able to determine value in the checks

    if score == 0
      print_error("#{tgt} is not a honeypot")
    elsif score < 0.4 && score != 0.0
      print_error("#{tgt} is probably not a honeypot")
    elsif score > 0.4 && score < 0.6
      print_status("#{tgt} might be a honeypot")
    elsif score > 0.6 && score < 1.0
      print_good("#{tgt} is probably a honeypot")
    elsif score == 1.0
      print_good("#{tgt} is definitely a honeypot")
    else  # We shouldn't ever get here as the previous checks should catch an unexpected response
      print_error('An unexpected error occurred.')
      return
    end
    print_score(score)
  end
end
