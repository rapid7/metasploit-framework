#!/usr/bin/env ruby

require 'net/http'
require 'json'

module Rex
  module Google
    # @example
    #   g = Rex::Google::Geolocation.new
    #   g.add_wlan("00:11:22:33:44:55", "example", -80)
    #   g.fetch!
    #   puts g, g.google_maps_url
    class Geolocation
      GOOGLE_API_URI = "https://maps.googleapis.com/maps/api/browserlocation/json?browser=firefox&sensor=true&"

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
        @uri.query << @wlan_list.take(10).join("&wifi=")
        request = Net::HTTP::Get.new(@uri.request_uri)
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl = true
        response = http.request(request)

        if response && response.code == '200'
          results = JSON.parse(response.body)
          self.latitude = results["location"]["lat"]
          self.longitude = results["location"]["lng"]
          self.accuracy = results["accuracy"]
        else
          msg = "Failure connecting to Google for location lookup."
          msg += " Code #{response.code} for query #{@uri}" if response
          fail msg
        end
      end

      # Add an AP to the list to send to Google when {#fetch!} is called.
      #
      # Turns out Google's API doesn't really care about ESSID or signal strength
      # as long as you have BSSIDs. Presumably adding them will make it more
      # accurate? Who knows.
      #
      # @param mac [String] in the form "00:11:22:33:44:55"
      # @param ssid [String] ESSID associated with the mac
      # @param signal_strength [String] a thing like
      def add_wlan(mac, ssid = nil, signal_strength = nil)
        @wlan_list.push(URI.encode("mac:#{mac.upcase}|ssid:#{ssid}|ss=#{signal_strength.to_i}"))
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
