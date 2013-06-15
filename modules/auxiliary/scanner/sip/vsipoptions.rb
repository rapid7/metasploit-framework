##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'digest/md5'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
        include Msf::Auxiliary::SIP

	def initialize
		super(
			'Name'        => 'SIP Options Discovery (UDP)',
			'Version'     => '1',
			'Description' => 'Options Discovery Module for SIP Services',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
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



		start_sipsrv(listen_port,listen_addr,dest_port,dest_addr)

		result,rdata,rdebug,rawdata = send_options(
			'realm'		=> realm,
			'from'    	=> from,
			'to'    	=> to
		)  

		case result
		when :received
			report = "#{rdata['source']}\tResponse: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}\n"
			report <<"Server \t: #{rdata['server']}\n" if rdata['server']
			report << "User-Agent \t: #{rdata['agent']}\n"	if rdata['agent']
			print_good(report)

			report_auth_info(
				:host	=> dest_addr,
				:port	=> datastore['RPORT'],
				:sname	=> 'sip',
				:proof  => nil,
				:source_type => "user_supplied",
				:active => true
			)
		else
			vprint_status("#{dest_addr}:#{dest_port} : #{convert_error(result)}")
		end

		#Debug
		if datastore['DEBUG'] == true
			if rdata !=nil
				report = "#{rdata['source']}\tresponse: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}\n"
				report <<"Server \t: #{rdata['server']}\n" if rdata['server']
				report <<"User-Agent \t: #{rdata['agent']}\n"	if rdata['agent']
				report <<"Realm \t: #{rdata['digest']['realm']}\n" if rdata['digest']
				print_debug(report)
			end

			rawdata.split("\n").each { |r| print_debug("Response Details: #{r}") } if rdata != nil
			rdebug.each { |r| print_debug("Irrelevant Responses :  #{r['resp']} #{r['resp_msg']}") } if rdebug
		end	
    end
end

