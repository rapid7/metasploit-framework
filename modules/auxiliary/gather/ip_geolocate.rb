##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'json'

class MetasploitModule < Msf::Auxiliary

  include Rex::Proto::Http
  include Msf::Exploit::Remote::HttpClient
  # HttpClient is only included because of normalize_uri

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'IP Based Geolocation',
      'Description'    => %q{
        This module uses a GeoIP API to locate the location
        of a given IP address. Even though an external API is being
        used, a API key is not needed for the module to work properly.
        The shown longitude and latitude values are estimations.
        If you want a more exact location, use the `wlan_geolocate` module.
      },
      'Author'         => [ 'Carter Brainerd <0xCB@protonmail.com>' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new("RHOSTS", [true, "A comma separated list of addresses to scan", nil])
      ])

    deregister_options( 'RHOST', 'SSL', 'RPORT', 'VHOST', 'Proxies' )
  end

  def gmap_url(lat, long)
    "https://maps.google.com/?q=#{lat},#{long}"
  end

  def valid_ipv4?(host)
    block = /\d{,2}|1\d{2}|2[0-4]\d|25[0-5]/
    re = /\A#{block}\.#{block}\.#{block}\.#{block}\z/
    return re =~ host
  end


  def run
    raw_rhosts = datastore['RHOSTS']
    rhosts = raw_rhosts.split(',')
    rhosts.each do |host|

      host.strip!  # Just in cast there are spaces in there
      if host.length <= 15
        if valid_ipv4?(host) != 0  # Check if each ip address is valid
          print_error("#{host} is not a valid IP address.")
          next
        end
      end

      # Because we're requesting an external site, we aren't actually requesting `rhost`
      # We're requesting the API and passing `rhost` in the URI.
      # This is why Rex::Proto::Http is being used and not send_request_cgi from HttpClient
      uri = normalize_uri('json', "#{host}")
      cli = Client.new('freegeoip.net', 80, {}, false)  # The API uses only HTTP unfortunately
      cli.connect
      req = cli.request_cgi({ 'uri' => uri })
      res = cli.send_recv(req)

      if res.nil?
        print_error('Got an empty response from the API')
        next
      end

      if res.code != 200
        print_error("Got an unexpected response from the API (Code: #{res.code})")
        next
      end

      parsed = JSON.parse(res.body)  # Make it fun to use (hash)
      print_line
      print_status("Data for #{host}")
      print_line("  Country: #{parsed['country_name']} (#{parsed['country_code']})")  # Print the country and country country code
      print_line("  City: #{parsed['region_name']} (#{parsed['region_code']})")       # Print the city and city code
      print_line("  Zip Code: #{parsed['zip_code']}")                                 # Print the zip code
      print_line("  Latitude: #{parsed['latitude']} (estimation)")                    # Print the latitude
      print_line("  Longitude: #{parsed['longitude']} (estimation)")                  # Print the longitude
      print_line("  Google Maps URL: #{gmap_url(parsed['latitude'], parsed['longitude'])}")
    end
  end
end
