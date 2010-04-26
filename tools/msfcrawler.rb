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
require 'pathname'
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
$threadnum = 20

# Dont crawl
$dontcrawl = ".exe,.zip,.tar,.bz2,.run,.asc,.gz,"

# Use proxy
$useproxy = false

# Proxy host
$proxyhost = '127.0.0.1'

# Proxy Port
$proxyport = 8080

# Cookie Jar
$cookiejar = {}

# Verbose
$verbose = false

# Enable URI Limits
$enableul = true

# Maximum number of requests per URI (check $enableul)
$maxurilimit = 1



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
				'query'		=> nil,
				'data'		=> nil
		}
	
	
		@NotViewedQueue = Rinda::TupleSpace.new
		@ViewedQueue = Hash.new
		@UriLimits = Hash.new
		
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
			'query'		=> nil,
			'data'		=> nil	
		}

		return hreq
	end
	
	def storedb(hashreq,response,dbpath)
		#postgres , pg gem
	
		db = SQLite3::Database.new(dbpath)
		#db = Mysql.new("127.0.0.1", username, password, databasename)
		until !db.transaction_active?
			#puts "Waiting for db"
			#wait
		end
		#puts "db: #{db.transaction_active?}"
		
		#CREATE TABLE "wmap_requests" (
		# "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
		# "host" varchar(255), 
		# "address" varchar(16), 
		# "address6" varchar(255), 
		# "port" integer, 
		# "ssl" integer, 
		# "meth" varchar(32), 
		# "path" text, 
		# "headers" text, 
		# "query" text, 
		# "body" text, 
		# "respcode" varchar(16), 
		# "resphead" text, 
		# "response" text, 
		# "created_at" datetime);
		

		db.transaction db.execute( "insert into wmap_requests (host,address,address6,port,ssl,meth,path,headers,query,body,respcode,resphead,response,created_at,updated_at) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			hashreq['rhost'],
			hashreq['rhost'],
			hashreq['rhost'], 
			hashreq['rport'].to_i,
			hashreq['ssl']? 1:0,
			hashreq['method'],
			SQLite3::Blob.new(hashreq['uri']),
			SQLite3::Blob.new(''),
			SQLite3::Blob.new(hashreq['query']? hashreq['query']:''),
			SQLite3::Blob.new(hashreq['data']? hashreq['data']:''),
			response.code.to_s,
			SQLite3::Blob.new(''),
			SQLite3::Blob.new(response.body.to_s),
			Time.new,
			Time.new
		) 
		db.commit
		
		db.close
	end
	
	def run
		i, a = 0, []
		
		
	
		begin
			reqfilter = reqtemplate(self.ctarget,self.cport,self.cssl)
								
			loop do
				
				####
				#if i <= $threadnum
				#	a.push(Thread.new {
				####
			
				hashreq = @NotViewedQueue.take(reqfilter, $taketimeout)
				
				ul = false				
				if @UriLimits.include?(hashreq['uri']) and $enableul
					#puts "Request #{@UriLimits[hashreq['uri']]}/#{$maxurilimit} #{hashreq['uri']}"	
					if @UriLimits[hashreq['uri']] >= $maxurilimit 
						#puts "URI LIMIT Reached: #{$maxurilimit} for uri #{hashreq['uri']}" 
						ul = true					
					end
 				else
					@UriLimits[hashreq['uri']] = 0	
				end
									
				if !@ViewedQueue.include?(hashsig(hashreq)) and !ul 
							
					@ViewedQueue[hashsig(hashreq)] = Time.now
					@UriLimits[hashreq['uri']] += 1
					
					if !File.extname(hashreq['uri']).empty? and $dontcrawl.include? File.extname(hashreq['uri'])
						if $verbose
							puts "URI not crawled #{hashreq['uri']}"
						end
					else	 
							
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
							
						

					end		
				else
					if $verbose
						puts "#{hashreq['uri']} already visited at #{@ViewedQueue[hashsig(hashreq)]}"
					end
				end
				
				####
				#})

				#i += 1	
				#else
				#	sleep(0.01) and a.delete_if {|x| not x.alive?} while not a.empty?
				#	i = 0
				#end
				####
					
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
				if resp['Set-Cookie']
					#puts "Set Cookie: #{resp['Set-Cookie']}"
					#puts "Storing in cookie jar for host:port #{reqopts['rhost']}:#{reqopts['rport']}"
					#$cookiejar["#{reqopts['rhost']}:#{reqopts['rport']}"] = resp['Set-Cookie']		
				end
				
				if $dbs
					storedb(reqopts,resp,$dbpathmsf)
				end
				
				puts ">> [#{resp.code}] #{reqopts['uri']}"
		
				if reqopts['query'] and !reqopts['query'].empty?
					puts ">>> [Q] #{reqopts['query']}" 
				end

				if reqopts['data'] 
					puts ">>> [D] #{reqopts['data']}" 
				end
				
				case resp.code
				when 200
					@crawlermodules.each_key do |k|
						@crawlermodules[k].parse(reqopts,resp)
					end
				when 301..303
					puts "[#{resp.code}] Redirection to: #{resp['Location']}"
					if $verbose
						puts urltohash('GET',resp['Location'],reqopts['uri'],nil)
					end
					insertnewpath(urltohash('GET',resp['Location'],reqopts['uri'],nil))
				when 404
					puts "[404] Invalid link #{reqopts['uri']}"	
				else
					puts "Unhandled #{resp.code}"
				end	
				
			else
				puts "No response"
			end
			sleep($sleeptime)			
		rescue
			puts "ERROR"
			if $verbose
				puts "#{$!}: #{$!.backtrace}"
			end
		end
	end

	#
	# Add new path (uri) to test non-viewed queue
	#
	def insertnewpath(hashreq)

		hashreq['uri'] = canonicalize(hashreq['uri'])

		if hashreq['rhost'] == self.ctarget and hashreq['rport'] == self.cport
			if !@ViewedQueue.include?(hashsig(hashreq)) 
				if @NotViewedQueue.read_all(hashreq).size > 0
					if $verbose
						puts "Already in queue to be viewed"
					end
				else
					if $verbose
						puts "Inserted: #{hashreq['uri']}"
					end
					
					@NotViewedQueue.write(hashreq)
				end			
			else
				if $verbose
					puts "#{hashreq['uri']} already visited at #{@ViewedQueue[hashsig(hashreq)]}"
				end
			end
		end
	end
	
	#
	# Build a new hash for a local path
	#
	
	def urltohash(m,url,basepath,dat)
			# m:   method
			# url: uri?[query]
			# basepath: base path/uri to determine absolute path when relative
			# data: body data, nil if GET and query = uri.query
		
			uri = URI.parse(url)
			uritargetssl = (uri.scheme == "https") ? true : false
						
			uritargethost = uri.host
			if (uri.host.nil? or uri.host.empty?) 
				uritargethost = self.ctarget
				uritargetssl = self.cssl
			end
			
			uritargetport = uri.port
			if (uri.port.nil?) 
				uritargetport = self.cport
			end

			uritargetpath = uri.path
			if (uri.path.nil? or uri.path.empty?) 
				uritargetpath = "/"
			end

			newp = Pathname.new(uritargetpath)
			oldp = Pathname.new(basepath)
			if !newp.absolute?
				if oldp.to_s[-1,1] == '/'
					newp = oldp+newp
				else
					if !newp.to_s.empty?
						newp = File.join(oldp.dirname,newp)
					end
				end		
			end		
		
			hashreq = {
				'rhost'		=> uritargethost,
				'rport'		=> uritargetport,
				'uri' 		=> newp.to_s,
				'method'   	=> m,
				'ctype'		=> 'text/plain',
				'ssl'		=> uritargetssl,
				'query'		=> uri.query,
				'data'		=> nil
			}

			if m == 'GET' and !dat.nil?
				hashreq['query'] = dat
			else
				hashreq['data'] = dat	  
			end
			
			
		
			return hashreq
	end
	
	# Taken from http://www.ruby-forum.com/topic/140101 by  Rob Biedenharn
	def canonicalize(uri)
   		u = uri.kind_of?(URI) ? uri : URI.parse(uri.to_s)
   		u.normalize!
   		newpath = u.path
   		while newpath.gsub!(%r{([^/]+)/\.\./?}) { |match|
              		$1 == '..' ? match : ''
            	} do end
   		newpath = newpath.gsub(%r{/\./}, '/').sub(%r{/\.\z}, '/')
   		u.path = newpath
		# Ugly fix
		u.path = u.path.gsub("\/..\/","\/")
   		u.to_s
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

	def urltohash(m,url,basepath,dat)
		self.crawler.urltohash(m,url,basepath,dat)	
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
			"-h" => [ false, "Display this help information"],
			"-v" => [ false, "Verbose" ]
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
		when "-v"
			$verbose = true		
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

	if $enableul
		puts "URI LIMITS ENABLED: #{$maxurilimit}"
	end

	puts "Target: #{mc.ctarget} Port: #{mc.cport} Path: #{mc.cinipath} SSL: #{mc.cssl}"
	mc.run	
end


		
		
	
