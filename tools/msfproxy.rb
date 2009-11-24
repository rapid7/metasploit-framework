#!/usr/bin/env ruby
#
# MITM proxy. 
#
# Author: et [at] metasploit.com 2009
#

# openssl before rubygems mac os
require 'openssl'
require 'rubygems'
require 'httpclient'
require 'eventmachine'

begin
	require 'sqlite3'
rescue LoadError
	puts "Error: sqlite3-ruby not found"
end
	
msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'

#
# Server properties
#
defaultport = 8080
defaultip = '0.0.0.0'

$storedb = false
$storedbpath = './sqlite3.db'
$tmode = false
$ttarget = ""
$tssl = false

#
# Print request/response/connect
#
$printcon = false
$printreq = false
$printres = false
$printstatus = false

$modulepname =  nil

#
# Used by modules for data storage
#
$modstore = {}

module HttpProxy
	def initialize
		@isssl = false
		@sslconnectdone = false
		
		if $modulepname
			m = ::Module.new
			begin
				m.module_eval(File.read($modulepname, File.size($modulepname)))
				m.constants.grep(/^Tamper(.*)/) do
					mname = $1
					klass = m.const_get("Tamper#{mname}")
					$modclass = klass.new()
 
					#puts("Loaded proxy module #{mname} from #{$modulepname}...")
				end
			rescue ::Exception => e
				puts("Proxy failed to load module: #{e.class} #{e}")
				exit
			end
		end
	end
	
	def post_init
		if $printcon
			client = Socket.unpack_sockaddr_in(get_peername)  
			puts "Received a new connection from #{client.last}:#{client.first}"
		end
		#
		# Only for transparent mode
		#
		if $tmode and $tssl
			start_tls
		end
	end
	
	def get_first_line(data)
		#
		# Just the first line
		#
		firstline = ""
		data.each do |line|
			firstline = line.chomp
			break
		end
				
		return firstline
	end
		
	def parse_target_array(target,ssl) 
		tarr = []
		
		#	
		# Clean garbage from target string and return [host,port,pathquery]
		#
		puri = target.sub(/^https:\/+|^http:\/+/,"")
		ppath = puri.scan(/\/.+|\//)
		tarr = puri.sub(/\/.+|\//,"").split(/:/)
			
		if !tarr[1]
			if ssl
				tarr[1] = 443
			else
				tarr[1] = 80
			end		
		end
				
		if ppath[0]
			tarr[2] = ppath[0]
		else
			tarr[2] = "/"
		end	
		return tarr
	end
		
	def receive_data(data)
		firstlinearray=[]
		
		#
		# Just for transparent mode
		#
		if $tmode 
			@sslconnectdone = true
			@isssl = true
		end
			
		if !@sslconnectdone
			firstlinestr = get_first_line(data)
			firstlinearray = firstlinestr.split(" ")
		else
			@isssl = true				
		end
				
		if !@isssl
			@targethost,@targetport,@targetpathquery = parse_target_array(firstlinearray[1], @usessl)
			if firstlinearray[0] and firstlinearray[0].include?("CONNECT")								
				send_data  "HTTP/1.0 200 Connection established\r\n\r\n"
				#start_tls(:verify_peer => false)
				start_tls
				@sslconnectdone = true
			else
				#
				# Adjust host:port/pathquery for /pathwuery on nonssl connection	
				#
				data["#{firstlinestr}"] = "#{firstlinearray[0]} #{@targetpathquery} #{firstlinearray[2]}" if data.include? firstlinestr
				handle_connection(data,@isssl)
			end
		else
			#
			# Just for transparent mode
			#
			if $tmode
				dumbstr =""
				@targethost,@targetport,dumbstr = parse_target_array($ttarget, $tssl)				
				handle_connection(data,$tssl)
			else
				handle_connection(data,@isssl)
			end
		end
	end	
		
	def handle_connection(request,usingssl)
		if $printreq
			p "REQUEST: #{request}"
		end
			
		# Use Rex::Proto::Http::Request to use
		# evasion techniques and allow to manipulate
		# request easily.
			
		modreq = Rex::Proto::Http::Request.new
		case modreq.parse(request)
			when Rex::Proto::Http::Packet::ParseCode::Completed
				
				# REQUEST INJECTION POINT
				if $modclass
					modreq = $modclass.tamper_request(modreq,usingssl)
				end
				# Done with user mods.
				
				if modreq.headers['Proxy-Connection']
					modreq.headers['Connection'] = 'close'
					modreq.headers.delete('Proxy-Connection')
				end									
					
				# Uncomment this line if you want to see clear text i.e. gzip
				#modreq.headers.delete('Accept-Encoding')
				
				# Adjust parsed request to httpclient										
				method = modreq.method					
				
				uri = "http://"	
				if usingssl
					uri = "https://"
				end
			
				uritarget = ""	
				uritarget << "#{@targethost}:#{@targetport}#{modreq.resource}"
				uri << uritarget
					
				query = modreq.qstring
				body = modreq.body		#modreq.data?			
				extheader = modreq.headers
				
				#	
				# Using httpclient so not to deal with rebuilding a ruby http client
				#																
				c = HTTPClient.new
				if usingssl
					c.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
				end
												
				begin
					# Send Request
					resp = c.request(method, uri, query, body, extheader)
				
					respstr = "HTTP/#{resp.version} "
					respstr << resp.status.to_s
					respstr << " "
					respstr << resp.reason
					respstr << "\r\n"
					
					hr = resp.header.all
					headstr = ""
					hr.collect { |var, val|
						if var == "Transfer-Encoding"
							headstr << "Content-Length: #{resp.content.length}\r\n"
						else
							headstr << "#{var}: #{val.to_s}\r\n"
						end
					}
					headstr << "\r\n"					
					respstr << headstr
					respstr << resp.content

					if $printstatus 
						puts "[-] #{resp.status.to_s}\t#{@targethost}\t#{modreq.resource}\t#{modreq.method} #{resp.content.length}"
					end
					#
					# store request and response in Metasploit
					# sqlite3 db
					#
					if $storedb
						sslint = 0
						if usingssl
							sslint = 1
						end
						
						strq = ""
						modreq.qstring.each_pair do |k,v|
							if strq.empty?
								strq = k + "=" + v
							else
								strq = k + "=" + v + "&"+ strq	
							end
						end
						
				
						# Using $db as connection
						Thread.new{
							$db.execute( "insert into requests values ( ?,?,?,?,?,?,?,?,?,?,?,?)", 
								@targethost, 
								@targetport,
								sslint,
								modreq.method,
								SQLite3::Blob.new(modreq.resource),
								SQLite3::Blob.new(modreq.headers.to_s),
								SQLite3::Blob.new(strq),
								SQLite3::Blob.new(modreq.body),
								resp.status.to_s,
								SQLite3::Blob.new(headstr),
								SQLite3::Blob.new(resp.content),
								Time.new
							)
						}.join			
					end

					#	
					# Response
					#
					
					# RESPONSE INJECTION POINT
					if $modclass
						respstr = $modclass.tamper_response(respstr,usingssl)
					end
					# Done with user mods.
					
					if $printres
						p "RESPONSE: #{respstr}"
					end																
					
					# Send response to client	
					send_data respstr
					
				rescue HTTPClient::ConnectTimeoutError => exc
					# Can configure connection timeout via HTTPClient#connect_timeout=. 
					puts "Error: ConnectTimeoutError to #{@targethost}: #{exc.message}"
				rescue HTTPClient::ReceiveTimeoutError => exc
					# Can configure connection timeout via HTTPClient#receive_timeout=. 
					puts "Error: ReceiveTimeoutError to #{@targethost}: #{exc.message}"
				end					
			when Rex::Proto::Http::Packet::ParseCode::Error
				p "Parsing Error!!!"
		end			
		unbind
	end
		
	def unbind
		self.close_connection_after_writing 
	end
end

def usage
	$stderr.puts("\n" + "    Usage: #{$0} <options>\n" + $args.usage)
	exit
end

$args = Rex::Parser::Arguments.new(
	"-a" => [ false, "Print requests: Default false" ],
	"-b" => [ false, "Print responses: Default false" ],
	"-c" => [ false, "Print connection message: Default false"],
	"-u" => [ false, "Print status: Default false"],
	"-v" => [ false, "Print requests and responses: Default false" ],	
	"-i" => [ true,  "Listening IP address. Default 0.0.0.0" ],
	"-p" => [ true,  "Listening proxy port. Default 8080"    ],
	"-w" => [ true,  "Store requests to Metasploit database <path>."  ],
	"-t" => [ true,  "Transparent mode. http(s)://host:port." ],
	"-m" => [ true,  "Load module. path/module.rb."],
	"-h" => [ false,  "Display this help information"         ])
			
$args.parse(ARGV) { |opt, idx, val|
	case opt
	when "-a"
		$printreq = true
	when "-b"
		$printres = true
	when "-c"
		$printcon = true
	when "-u"
		$printstatus = true		
	when "-v"
		$printreq = true
		$printres = true
		$printcon = true	
	when "-w"		
		$storedbpath = val
		$storedb = true
		puts "Storing requests in #{$storedbpath}."
		$db = SQLite3::Database.new($storedbpath)		
	when "-i"
		defaultip = val
	when "-m"
		$modulepname = val
	when "-p"
		defaultport = val
	when "-t"
		$tmode = true
		$ttarget = val
		puts "Transparent mode: #{$ttarget}"
		if $ttarget.include?("https://")
			$tssl = true
		end	 	
	when "-h"
		usage
	end
}		

EventMachine::run {
	puts "SSL Support: #{EM.ssl?}."
	
	EM.epoll
	EM::start_server(defaultip, defaultport, HttpProxy)
	puts "Listening on #{defaultip} port #{defaultport}."
}


