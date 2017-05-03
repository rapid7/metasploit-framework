##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'digest/md5'
require 'sipsocket'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
    include SIP

	def initialize
		super(
			'Name'        => 'SIP Options Discovery (UDP)',
			'Version'     => '1',
			'Description' => 'Options Discovery Module for SIP Services',
			'Author'      => 'Fatih Ozavci <gamasec.net/fozavci>',
			'License'     => MSF_LICENSE
		)
	
		register_options(
		[
			OptString.new('REALM',   [ true, "The login realm to probe at each host", "realm.com.tr"]),
			OptString.new('TO',   [ true, "The destination username to probe at each host", "100"]),
			OptString.new('FROM',   [ true, "The source username to probe at each host", "100"]),
			Opt::RPORT(5060),
			Opt::CHOST,	
			Opt::CPORT(5065)
		], self.class)

		register_advanced_options(
		[
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false])
		], self.class)
	end

    
	def run_host(dest_addr)

		udp_sock = nil

		realm = datastore['REALM']
		from = datastore['FROM']
		to = datastore['TO']
		listen_addr = datastore['CHOST']
		listen_port = datastore['CPORT'].to_i 
		dest_port = datastore['RPORT'].to_i 



		sipsocket = SIP::Socket.new(listen_port,listen_addr,dest_port,dest_addr)

		result,rdata,rdebug,rawdata = sipsocket.send_options(
			'realm'		=> realm,
			'from'    	=> from,
			'to'    		=> to
		)  

		case result
		when :received
			print_good("#{rdata['source']}\tResponse: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}")
			print_good("Server \t: #{rdata['server']}") if rdata['server']
			print_good("User-Agent \t: #{rdata['agent']}")	if rdata['agent']

			#Debug
			if datastore['DEBUG'] == true
				rdebug.each do |r| print_status("debug: #{r['resp']} #{r['resp_msg']}") end
				rawdata.split("\n").each do |r| print_status("debug: #{r}") end
			end

			report_auth_info(
				:host	=> dest_addr,
				:port	=> datastore['RPORT'],
				:sname	=> 'sip',
				:proof  => nil,
				:source_type => "user_supplied",
				:active => true
			)
		else
			vprint_status("#{dest_addr}:#{dest_port} : #{sipsocket.convert_error(result)}")
		end

		#Debug
		if datastore['DEBUG'] == true
			if rdata !=nil
				print_debug("#{rdata['source']}\tresponse: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}")
				print_debug("Server \t: #{rdata['server']}") if rdata['server']
				print_debug("User-Agent \t: #{rdata['agent']}")	if rdata['agent']
				print_debug("Realm \t: #{rdata['digest']['realm']}") if rdata['digest']
			end

			rawdata.split("\n").each { |r| print_debug("Response Details: #{r}") } if rdata != nil
			rdebug.each { |r| print_debug("Irrelevant Responses :  #{r['resp']} #{r['resp_msg']}") } if rdebug
		end	
    end
end

