#!/usr/bin/env ruby
#
# Web Crawler. 
#
# Author: et [at] metasploit.com 2010
#
#

# openssl before rubygems mac os
require 'openssl'
require 'rubygems'
require 'rinda/tuplespace'
require 'uri'

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


# Sleep time (secs) between requests
$sleeptime = 0

# Timeout for loop ending
$taketimeout = 15

# Read timeout (-1 forever)
$readtimeout = -1	

# Directory containing crawler modules
$crawlermodulesdir =  File.join(File.dirname(msfbase),"..", "data", "msfcrawler")

# Database
$dbpathmsf = File.join(Msf::Config.get_config_root, 'sqlite3.db')

# Store in database?
$dbs = false

# Thread number
$threadnum = 1

# Use proxy
$useproxy = false

# Proxy host
$proxyhost = '127.0.0.1'

# Proxy Port
$proxyport = 8080

class HttpCrawler
	attr_accessor :ctarget, :cport, :cinipath, :cssl, :proxyhost, :proxyport, :useproxy

	def initialize(target,port,inipath,ssl,proxyhost,proxyport,useproxy)
		self.ctarget = target
		self.cport = port
		self.cssl = ssl
		
		self.useproxy = useproxy
		self.proxyhost = proxyhost
		self.proxyport = proxyport
		
		self.cinipath = (inipath.nil? or inipath.empty?) ? '/' : inipath
					
		inireq = {
				'rhost'		=> self.ctarget,
				'rport'		=> self.cport,
				'uri' 		=> self.cinipath,
				'method'   	=> 'GET',
				'ctype'		=> 'text/plain',
				'ssl'		=> self.cssl,
				'query'		=> nil
		}
	
	
		@NotViewedQueue = Rinda::TupleSpace.new
		@ViewedQueue = Hash.new
		
		insertnewpath(inireq)
			
		puts "Loading modules: #{$crawlermodulesdir}"
		load_modules
		puts "OK"
	end
	
	def reqtemplate(target,port,ssl)
		hreq = {
			'rhost'		=> target,
			'rport'		=> port,
			'uri'  		=> nil,
			'method'   	=> nil,
			'ctype'		=> nil,
			'ssl'		=> ssl,
			'query'		=> nil
		}

		return hreq
	end
	
	def storedb(hashreq,response,dbpath)
		db = SQLite3::Database.new(dbpath)
		#db = Mysql.new("127.0.0.1", username, password, databasename)
		until !db.transaction_active?
			puts "Waiting for db"
			#wait
		end
		#puts "db: #{db.transaction_active?}"
		db.transaction db.execute( "insert into wmap_requests values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			nil,
			hashreq['rhost'],
			hashreq['rhost'],
			hashreq['rhost'], 
			hashreq['rport'].to_i,
			hashreq['ssl'],
			hashreq['method'],
			SQLite3::Blob.new(hashreq['uri']),
			SQLite3::Blob.new("a"),
			SQLite3::Blob.new("b"),
			SQLite3::Blob.new("c"),
			"200",
			SQLite3::Blob.new("d"),
			SQLite3::Blob.new("e"),
			Time.new
		) 
		db.commit
		
		db.close
	end
	
	def run
		i, a = 0, []
		
	
		begin			
			loop do
				hashreq = @NotViewedQueue.take(reqtemplate(self.ctarget,self.cport,self.cssl), $taketimeout)
				#puts hashreq					
				if !@ViewedQueue.include?(hashsig(hashreq))
					@ViewedQueue[hashsig(hashreq)] = Time.now
					
					#if i < $threadnum
					#	a.push(Thread.new {
							
							prx = nil
							if self.useproxy
								prx = "HTTP:"+self.proxyhost.to_s+":"+self.proxyport.to_s
							end

							c = Rex::Proto::Http::Client.new(
								self.ctarget,
								self.cport.to_i,
								{},
								self.cssl,
								nil,
								prx
							)

											
							sendreq(c,hashreq)

					#	})

					#	i += 1	
					#else
					#	sleep(0.01) and a.delete_if {|x| not x.alive?} while not a.empty?
					#	i = 0
					#end		
				else
					#puts "#{hashreq} already visited at #{@ViewedQueue[hashsig(hashreq)]}"
				end
					
			end	 												
		rescue Rinda::RequestExpiredError
			puts "END."
			return
		end
	end
		
	#
	# Modified version of load_protocols from psnuffle by Max Moser  <mmo@remote-exploit.org>
	#
	def load_modules
		base = $crawlermodulesdir
		if (not File.directory?(base))
			raise RuntimeError,"The Crawler modules parameter is set to an invalid directory"
		end
		
		@crawlermodules = {}
		cmodules = Dir.new(base).entries.grep(/\.rb$/).sort
		cmodules.each do |n|
			f = File.join(base, n)
			m = ::Module.new
			begin
				m.module_eval(File.read(f, File.size(f)))
				m.constants.grep(/^Crawler(.*)/) do
					cmod = $1
					klass = m.const_get("Crawler#{cmod}")
					@crawlermodules[cmod.downcase] = klass.new(self)
					
					puts("Loaded crawler module #{cmod} from #{f}...")
				end
			rescue ::Exception => e
				puts("Crawler module #{n} failed to load: #{e.class} #{e} #{e.backtrace}")
			end
		end
	end
	
	def sendreq(nclient,reqopts={})		
		
		puts ">> #{reqopts['uri']}"
		
		if reqopts['query']
			puts ">>> #{reqopts['query']}" 
		end
		
		begin
			r = nclient.request_raw(reqopts)
			resp = nclient.send_recv(r, $readtimeout)
			while(resp and resp.code == 100)
				resp = nclient.reread_response(resp, $readtimeout)
			end			
			
			if resp
				#
				# Quickfix for bug packet.rb to_s line: 190
				# In case modules or crawler calls to_s on de-chunked responses 
				#
				resp.transfer_chunked = false
				#puts ("#{resp.to_s}")
				
				#puts "resp code #{resp.code}"
				
				if $dbs
					#store db
					storedb(reqopts,resp,$dbpathmsf)
				end
				
				case resp.code
				when 200
					@crawlermodules.each_key do |k|
						@crawlermodules[k].parse(reqopts,resp)
					end
				when 301
					puts "Redirection"	
				when 404
					puts "Invalid link (404) #{reqopts['uri']}"	
				else
					puts "Unhandled #{resp.code}"
				end	
			else
				puts "No response"
			end
			sleep($sleeptime)
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end
	end

	#
	# Add new path (uri) to test non-viewed queue
	#
	def insertnewpath(hashreq)
		if hashreq['rhost'] == self.ctarget and hashreq['rport'] == self.cport
			if !@ViewedQueue.include?(hashsig(hashreq)) 
				if @NotViewedQueue.read_all(hashreq).size > 0
					#puts "Already in queue to be viewed"
				else					
					#puts "I: #{hashreq['uri']}"
					@NotViewedQueue.write(hashreq)
				end			
			else
				#puts "#{hashreq} already visited at #{@ViewedQueue[hashsig(hashreq)]}"
			end
		end
	end
	
	def hashsig(hashreq)
		hashreq.to_s
	end

end	

class BaseParser
	attr_accessor :crawler
 
	def initialize(c)
		self.crawler = c
	end 

	def parse(request,result)
		nil
	end
	
	#
	# Add new path (uri) to test hash queue
	#
	def insertnewpath(hashreq)
		self.crawler.insertnewpath(hashreq)
	end
	
	def hashsig(hashreq)
		self.crawler.hashsig(hashreq)
	end
	
	def targetssl
		self.crawler.cssl
	end
	
	def targetport
		self.crawler.cport
	end
	
	def targethost
		self.crawler.ctarget
	end
	
	def targetinipath
		self.crawler.cinipath
	end
end


trap("INT") { 
	exit()
}

$args = Rex::Parser::Arguments.new(
			"-t" => [ true,  "Target URI" ],
			"-d" => [ false, "Enable database" ],
			"-u" => [ true, "Use proxy"],
			"-x" => [ true, "Proxy host" ],
			"-p" => [ true, "Proxy port" ],
			"-h" => [ false, "Display this help information"]
		)
	
if ARGV.length < 1 
	puts("\n" + "    Usage: #{$0} <options>\n" + $args.usage)
	exit
end		
 
turl = nil											   						                       
$args.parse(ARGV) { |opt, idx, val|
        case opt
		when "-d"
			$dbs = true
 		when "-t"
			$crun = true
			turl = val
		when "-u"
			$useproxy = true	
		when "-x"
			$proxyhost = val
		when "-p"
			$proxyposrt = val										
        when "-h"
			puts("\n" + "    Usage: #{$0} <options>\n" + $args.usage)
			exit
        end
}		

if $crun
	uri = URI.parse(turl)
	tssl = (uri.scheme == "https") ? true : false
			
	if (uri.host.nil? or uri.host.empty?) 
		puts "Error: target http(s)://target/path"
		exit
	end
	
	if $useproxy
		puts "Using proxy: #{$proxyhost}:#{$proxyport}" 
	end
	
	mc = HttpCrawler.new(uri.host,uri.port,uri.path,tssl,$proxyhost, $proxyport, $useproxy)
	if $dbs
		puts "Database: #{$dbpathmsf}"
	else
		puts "[DATABASE DISABLED]"
	end
	puts "Target: #{mc.ctarget} Port: #{mc.cport} Path: #{mc.cinipath} SSL: #{mc.cssl}"
	mc.run	
end


		
		
	
