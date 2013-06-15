##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'rex/proto/sip'

class Metasploit3 < Msf::Auxiliary

        include Msf::Auxiliary::Report
        include Msf::Auxiliary::SIP

	def initialize
		super(
			'Name'        => 'SIP Proxy with Auto Replace Support',
			'Version'     => '$Revision$',
			'Description' => 'SIP Proxy with Auto Replace Support',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)

		deregister_options('RHOST','RHOSTS','RPORT')
		register_options(
		[
			OptAddress.new('PRXCLT_IP',   [true, 'Local IP of SIP Server for Client']),
			OptInt.new('PRXCLT_PORT',   [true, 'Local UDP Port of SIP Server for Client',5061]),
			OptAddress.new('PRXSRV_IP',   [true, 'Local IP of SIP Server for Server']),
			OptInt.new('PRXSRV_PORT',   [true, 'Local UDP Port of SIP Server for Server',5060]),
			OptAddress.new('CLIENT_IP',   [true, 'IP of SIP Client']),
			OptInt.new('CLIENT_PORT',   [true, 'Port of SIP Client',5060]),
			OptAddress.new('SERVER_IP',   [true, 'IP of Remote SIP Server']),
			OptInt.new('SERVER_PORT',   [true, 'Port of Remote SIP Server',5060]),
			OptPath.new('CONF_FILE',      [ false, "File containing Replacements, one per line",
			#File.join(Msf::Config.install_root, "data", "wordlists", "sipproxy_replace.txt") ]),
			File.join("/", "tmp", "sipproxy_replace.txt") ]),
			OptBool.new('LOG',      [ true, "Logging for Requests and Responses", false]),
		], self.class)

		register_advanced_options(
		[
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false])
		], self.class)
	end

	def run
	 	client_ip = datastore['CLIENT_IP']
	 	client_port = datastore['CLIENT_PORT']
	 	server_ip = datastore['SERVER_IP']
	 	server_port = datastore['SERVER_PORT']

	 	prxclient_ip = datastore['PRXCLT_IP']
	 	prxclient_port = datastore['PRXCLT_PORT']
	 	prxserver_ip = datastore['PRXSRV_IP']
	 	prxserver_port = datastore['PRXSRV_PORT']


		start_sipprx(prxclient_port,prxclient_ip,client_port,client_ip,prxserver_port,prxserver_ip,server_port,server_ip)
		set_replacefile(datastore['CONF_FILE']) if datastore['CONF_FILE']
		set_logfile(File.join("/", "tmp", "sipproxylog-#{rand(0x10000000)}.log")) if datastore['LOG']
		start_monitor

		begin
		        # Wait for finish...
		        while self.thread.alive?
		                select(nil, nil, nil, 2)
		        end
		rescue 
			nil
		ensure
			stop		
		end
	end

end
