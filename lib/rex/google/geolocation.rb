#!/usr/bin/env ruby

require 'net/http'
require 'json'

module Rex
  module Google
    # @example
    #   g = Rex::Google::Geolocation.new
    #   g.set_api_key('example')
    #   g.add_wlan("00:11:22:33:44:55", "example", -80)
    #   g.fetch!
    #   puts g, g.google_maps_url
    class Geolocation
      GOOGLE_API_URI = "https://www.googleapis.com/geolocation/v1/geolocate?key="

      attr_accessor :accuracy
      attr_accessor :latitude
      attr_accessor :longitude

      def initialize
        @uri = URI.parse(URI.encode(GOOGLE_API_URI))
        @wlan_list = []
      end

      # Ask Google's Maps API for the location of a given set of BSSIDs (MAC
      # addresses of access points), ESSIDs (AP names), and signal strengths.
      def fetch!        
        request = Net::HTTP::Post.new(@uri.request_uri)
        request.body = {'wifiAccessPoints' => @wlan_list}.to_json
        request['Content-Type'] = 'application/json'
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl = true
        response = http.request(request)

        msg = "Failure connecting to Google for location lookup."
        if response && response.code == '200'
          results = JSON.parse(response.body)
          self.latitude = results["location"]["lat"]
          self.longitude = results["location"]["lng"]
          self.accuracy = results["accuracy"]
        elsif response && response.body && response.code != '404' # we can json load and get a good error message
          msg += " Code #{results['error']['code']} for query #{@uri} with error #{results['error']['message']}"
          fail msg
        else
          msg += " Code #{response.code} for query #{@uri}" if response
          fail msg
        end
      end

      # Add an AP to the list to send to Google when {#fetch!} is called.
      #
      # @param mac [String] in the form "00:11:22:33:44:55"
      # @param signal_strength [String] a thing like
      def add_wlan(mac, signal_strength)
        @wlan_list.push({ :macAddress => mac.upcase.to_s, :signalStrength => signal_strength.to_s })
      end

      def set_api_key(key)
        @uri = URI.parse(URI.encode(GOOGLE_API_URI + key))
      end

      def google_maps_url
        "https://maps.google.com/?q=#{latitude},#{longitude}"
      end

      def to_s
        "Google indicates the device is within #{accuracy} meters of #{latitude},#{longitude}."
      end
    end
  end
end
