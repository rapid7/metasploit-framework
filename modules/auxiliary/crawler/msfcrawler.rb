##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

#
# Web Crawler.
#
# Author:  Efrain Torres   et [at] metasploit.com 2010
#
#

# openssl before rubygems mac os
require 'msf/core'
require 'openssl'
require 'rubygems'
require 'rinda/tuplespace'
require 'pathname'
require 'uri'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'Metasploit Web Crawler',
      'Description'       => 'This auxiliary module is a modular web crawler, to be used in conjuntion with wmap (someday) or standalone.',
      'Author'			=> 'et',
      'License'			=> MSF_LICENSE
    ))

    register_options([
      OptString.new('PATH',	[true,	"Starting crawling path", '/']),
      OptInt.new('RPORT', [true, "Remote port", 80 ]),
    ], self.class)

    register_advanced_options([
      OptPath.new('CrawlerModulesDir', [true,	'The base directory containing the crawler modules',
        File.join(Msf::Config.install_root, "data", "msfcrawler")
      ]),
      OptBool.new('EnableUl', [ false, "Enable maximum number of request per URI", true ]),
      OptBool.new('StoreDB', [ false, "Store requests in database", false ]),
      OptInt.new('MaxUriLimit', [ true, "Number max. request per URI", 10]),
      OptInt.new('SleepTime', [ true, "Sleep time (secs) between requests", 0]),
      OptInt.new('TakeTimeout', [ true, "Timeout for loop ending", 15]),
      OptInt.new('ReadTimeout', [ true, "Read timeout (-1 forever)", 3]),
      OptInt.new('ThreadNum', [ true, "Threads number", 20]),
      OptString.new('DontCrawl',	[true,	"Filestypes not to crawl", '.exe,.zip,.tar,.bz2,.run,.asc,.gz']),
    ], self.class)
  end

  attr_accessor :ctarget, :cport, :cssl

  def run
    i, a = 0, []

    self.ctarget = datastore['RHOSTS']
    self.cport = datastore['RPORT']
    self.cssl = datastore['SSL']
    inipath = datastore['PATH']

    cinipath = (inipath.nil? or inipath.empty?) ? '/' : inipath

    inireq = {
        'rhost'		=> ctarget,
        'rport'		=> cport,
        'uri' 		=> cinipath,
        'method'   	=> 'GET',
        'ctype'		=> 'text/plain',
        'ssl'		=> cssl,
        'query'		=> nil,
        'data'		=> nil
    }

    @NotViewedQueue = Rinda::TupleSpace.new
    @ViewedQueue = Hash.new
    @UriLimits = Hash.new
    @curent_site = self.ctarget

    insertnewpath(inireq)

    print_status("Loading modules: #{datastore['CrawlerModulesDir']}")
    load_modules(datastore['CrawlerModulesDir'])
    print_status("OK")

    if datastore['EnableUl']
      print_status("URI LIMITS ENABLED: #{datastore['MaxUriLimit']} (Maximum number of requests per uri)")
    end

    print_status("Target: #{self.ctarget} Port: #{self.cport} Path: #{cinipath} SSL: #{self.cssl}")


    begin
      reqfilter = reqtemplate(self.ctarget,self.cport,self.cssl)

      i =0

      loop do

        ####
        #if i <= datastore['ThreadNum']
        #	a.push(Thread.new {
        ####

        hashreq = @NotViewedQueue.take(reqfilter, datastore['TakeTimeout'])

        ul = false
        if @UriLimits.include?(hashreq['uri']) and datastore['EnableUl']
          #puts "Request #{@UriLimits[hashreq['uri']]}/#{$maxurilimit} #{hashreq['uri']}"
          if @UriLimits[hashreq['uri']] >= datastore['MaxUriLimit']
            #puts "URI LIMIT Reached: #{$maxurilimit} for uri #{hashreq['uri']}"
            ul = true
          end
        else
          @UriLimits[hashreq['uri']] = 0
        end

        if !@ViewedQueue.include?(hashsig(hashreq)) and !ul

          @ViewedQueue[hashsig(hashreq)] = Time.now
          @UriLimits[hashreq['uri']] += 1

          if !File.extname(hashreq['uri']).empty? and datastore['DontCrawl'].include? File.extname(hashreq['uri'])
            vprint_status "URI not crawled #{hashreq['uri']}"
          else
              prx = nil
              #if self.useproxy
              #	prx = "HTTP:"+self.proxyhost.to_s+":"+self.proxyport.to_s
              #end

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
          vprint_line "#{hashreq['uri']} already visited. "
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
      print_status("END.")
      return
    end

    print_status("Finished crawling")
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

    info = {
      :web_site => @current_site,
      :path     => hashreq['uri'],
      :query    => hashreq['query'],
      :data	=> hashreq['data'],
      :code     => response['code'],
      :body     => response['body'],
      :headers  => response['headers']
    }

    #if response['content-type']
    #	info[:ctype] = response['content-type'][0]
    #end

    #if response['set-cookie']
    #	info[:cookie] = page.headers['set-cookie'].join("\n")
    #end

    #if page.headers['authorization']
    #	info[:auth] = page.headers['authorization'].join("\n")
    #end

    #if page.headers['location']
    #	info[:location] = page.headers['location'][0]
    #end

    #if page.headers['last-modified']
    #	info[:mtime] = page.headers['last-modified'][0]
    #end

    # Report the web page to the database
    report_web_page(info)
  end

  #
  # Modified version of load_protocols from psnuffle by Max Moser  <mmo@remote-exploit.org>
  #

  def load_modules(crawlermodulesdir)

    base = crawlermodulesdir
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

          print_status("Loaded crawler module #{cmod} from #{f}...")
        end
      rescue ::Exception => e
        print_error("Crawler module #{n} failed to load: #{e.class} #{e} #{e.backtrace}")
      end
    end
  end

  def sendreq(nclient,reqopts={})

    begin
      r = nclient.request_raw(reqopts)
      resp = nclient.send_recv(r, datastore['ReadTimeout'])

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

        if datastore['StoreDB']
          storedb(reqopts,resp,$dbpathmsf)
        end

        print_status ">> [#{resp.code}] #{reqopts['uri']}"

        if reqopts['query'] and !reqopts['query'].empty?
          print_status ">>> [Q] #{reqopts['query']}"
        end

        if reqopts['data']
          print_status ">>> [D] #{reqopts['data']}"
        end

        case resp.code
        when 200
          @crawlermodules.each_key do |k|
            @crawlermodules[k].parse(reqopts,resp)
          end
        when 301..303
          print_line("[#{resp.code}] Redirection to: #{resp['Location']}")
          vprint_status urltohash('GET',resp['Location'],reqopts['uri'],nil)
          insertnewpath(urltohash('GET',resp['Location'],reqopts['uri'],nil))
        when 404
          print_status "[404] Invalid link #{reqopts['uri']}"
        else
          print_status "Unhandled #{resp.code}"
        end

      else
        print_status "No response"
      end
      sleep(datastore['SleepTime'])
    rescue
      print_status "ERROR"
      vprint_status "#{$!}: #{$!.backtrace}"
    end
  end

  #
  # Add new path (uri) to test non-viewed queue
  #

  def insertnewpath(hashreq)

    hashreq['uri'] = canonicalize(hashreq['uri'])

    if hashreq['rhost'] == datastore['RHOSTS'] and hashreq['rport'] == datastore['RPORT']
      if !@ViewedQueue.include?(hashsig(hashreq))
        if @NotViewedQueue.read_all(hashreq).size > 0
          vprint_status "Already in queue to be viewed: #{hashreq['uri']}"
        else
          vprint_status "Inserted: #{hashreq['uri']}"

          @NotViewedQueue.write(hashreq)
        end
      else
        vprint_status "#{hashreq['uri']} already visited at #{@ViewedQueue[hashsig(hashreq)]}"
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
