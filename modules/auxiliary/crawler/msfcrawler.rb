##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Web Crawler.
#
# Author:  Efrain Torres   et [at] metasploit.com 2010
#
#

# openssl before rubygems mac os
require 'English'
require 'openssl'
require 'pathname'
require 'uri'
require 'rinda/rinda'
require 'rinda/tuplespace'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Metasploit Web Crawler',
        'Description' => 'This auxiliary module is a modular web crawler, to be used in conjunction with wmap (someday) or standalone.',
        'Author' => 'et',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('PATH', [true, 'Starting crawling path', '/']),
      OptInt.new('RPORT', [true, 'Remote port', 80 ])
    ])

    register_advanced_options([
      OptPath.new(
        'CrawlerModulesDir',
        [
          true,
          'The base directory containing the crawler modules',
          File.join(Msf::Config.data_directory, 'msfcrawler')
        ]
      ),
      OptBool.new('EnableUl', [ false, 'Enable maximum number of request per URI', true ]),
      OptBool.new('StoreDB', [ false, 'Store requests in database', false ]),
      OptInt.new('MaxUriLimit', [ true, 'Number max. request per URI', 10]),
      OptInt.new('SleepTime', [ true, 'Sleep time (secs) between requests', 0]),
      OptInt.new('TakeTimeout', [ true, 'Timeout for loop ending', 15]),
      OptInt.new('ReadTimeout', [ true, 'Read timeout (-1 forever)', 3]),
      OptInt.new('ThreadNum', [ true, 'Threads number', 20]),
      OptString.new('DontCrawl', [true, 'Filestypes not to crawl', '.exe,.zip,.tar,.bz2,.run,.asc,.gz'])
    ])
  end

  attr_accessor :ctarget, :cport, :cssl

  def run
    # i = 0
    # a = []

    self.ctarget = datastore['RHOSTS']
    self.cport = datastore['RPORT']
    self.cssl = datastore['SSL']
    inipath = datastore['PATH']

    cinipath = (inipath.nil? || inipath.empty?) ? '/' : inipath

    inireq = {
      'rhost' => ctarget,
      'rport' => cport,
      'uri' => cinipath,
      'method' => 'GET',
      'ctype' => 'text/plain',
      'ssl' => cssl,
      'query' => nil,
      'data' => nil
    }

    @not_viewed_queue = ::Rinda::TupleSpace.new
    @viewed_queue = Hash.new
    @uri_limits = Hash.new
    @current_site = ctarget

    insertnewpath(inireq)

    print_status("Loading modules: #{datastore['CrawlerModulesDir']}")
    load_modules(datastore['CrawlerModulesDir'])
    print_status('OK')

    if datastore['EnableUl']
      print_status("URI LIMITS ENABLED: #{datastore['MaxUriLimit']} (Maximum number of requests per uri)")
    end

    print_status("Target: #{ctarget} Port: #{cport} Path: #{cinipath} SSL: #{cssl}")

    begin
      reqfilter = reqtemplate(ctarget, cport, cssl)

      # i = 0

      loop do
        ####
        # if i <= datastore['ThreadNum']
        #   a.push(Thread.new {
        ####

        hashreq = @not_viewed_queue.take(reqfilter, datastore['TakeTimeout'])

        ul = false
        if @uri_limits.include?(hashreq['uri']) && datastore['EnableUl']
          # puts "Request #{@uri_limits[hashreq['uri']]}/#{$maxurilimit} #{hashreq['uri']}"
          if @uri_limits[hashreq['uri']] >= datastore['MaxUriLimit']
            # puts "URI LIMIT Reached: #{$maxurilimit} for uri #{hashreq['uri']}"
            ul = true
          end
        else
          @uri_limits[hashreq['uri']] = 0
        end

        if !@viewed_queue.include?(hashsig(hashreq)) && !ul

          @viewed_queue[hashsig(hashreq)] = Time.now
          @uri_limits[hashreq['uri']] += 1

          if !File.extname(hashreq['uri']).empty? && datastore['DontCrawl'].include?(File.extname(hashreq['uri']))
            vprint_status "URI not crawled #{hashreq['uri']}"
          else
            prx = nil
            # if self.useproxy
            #   prx = "HTTP:"+self.proxyhost.to_s+":"+self.proxyport.to_s
            # end

            c = Rex::Proto::Http::Client.new(
              ctarget,
              cport.to_i,
              {},
              cssl,
              nil,
              prx
            )

            sendreq(c, hashreq)
          end
        else
          vprint_line "#{hashreq['uri']} already visited. "
        end

        ####
        # })

        # i += 1
        # else
        #   sleep(0.01) and a.delete_if {|x| not x.alive?} while not a.empty?
        #   i = 0
        # end
        ####
      end
    rescue ::Rinda::RequestExpiredError
      print_status('END.')
      return
    end

    print_status('Finished crawling')
  end

  def reqtemplate(target, port, ssl)
    hreq = {
      'rhost' => target,
      'rport' => port,
      'uri' => nil,
      'method' => nil,
      'ctype' => nil,
      'ssl' => ssl,
      'query' => nil,
      'data' => nil
    }

    return hreq
  end

  def storedb(hashreq, response)
    # Added host/port/ssl for report_web_page support
    info = {
      web_site: @current_site,
      path: hashreq['uri'],
      query: hashreq['query'],
      host: hashreq['rhost'],
      port: hashreq['rport'],
      ssl: !hashreq['ssl'].nil?,
      data: hashreq['data'],
      code: response.code,
      body: response.body,
      headers: response.headers
    }

    # if response['content-type']
    #   info[:ctype] = response['content-type'][0]
    # end

    # if response['set-cookie']
    #   info[:cookie] = page.headers['set-cookie'].join("\n")
    # end

    # if page.headers['authorization']
    #   info[:auth] = page.headers['authorization'].join("\n")
    # end

    # if page.headers['location']
    #   info[:location] = page.headers['location'][0]
    # end

    # if page.headers['last-modified']
    #   info[:mtime] = page.headers['last-modified'][0]
    # end

    # Report the web page to the database
    report_web_page(info)
  end

  #
  # Modified version of load_protocols from psnuffle by Max Moser  <mmo@remote-exploit.org>
  #

  def load_modules(crawlermodulesdir)
    base = crawlermodulesdir
    if !File.directory?(base)
      raise 'The Crawler modules parameter is set to an invalid directory'
    end

    @crawlermodules = {}
    cmodules = Dir.new(base).entries.grep(/\.rb$/).sort
    cmodules.each do |n|
      f = File.join(base, n)
      m = ::Module.new
      begin
        m.module_eval(File.read(f, File.size(f)))
        m.constants.grep(/^Crawler(.*)/) do
          cmod = ::Regexp.last_match(1)
          klass = m.const_get("Crawler#{cmod}")
          @crawlermodules[cmod.downcase] = klass.new(self)

          print_status("Loaded crawler module #{cmod} from #{f}...")
        end
      rescue StandardError => e
        print_error("Crawler module #{n} failed to load: #{e.class} #{e} #{e.backtrace}")
      end
    end
  end

  def sendreq(nclient, reqopts = {})
    r = nclient.request_raw(reqopts)
    resp = nclient.send_recv(r, datastore['ReadTimeout'])

    unless resp
      print_status('No response')
      sleep(datastore['SleepTime'])
      return
    end

    #
    # Quickfix for bug packet.rb to_s line: 190
    # In case modules or crawler calls to_s on de-chunked responses
    #
    resp.transfer_chunked = false

    if datastore['StoreDB']
      storedb(reqopts, resp)
    end

    print_status ">> [#{resp.code}] #{reqopts['uri']}"

    if reqopts['query'] && !reqopts['query'].empty?
      print_status ">>> [Q] #{reqopts['query']}"
    end

    if reqopts['data']
      print_status ">>> [D] #{reqopts['data']}"
    end

    case resp.code
    when 200
      @crawlermodules.each_key do |k|
        @crawlermodules[k].parse(reqopts, resp)
      end
    when 301..303
      print_line("[#{resp.code}] Redirection to: #{resp['Location']}")
      vprint_status urltohash('GET', resp['Location'], reqopts['uri'], nil)
      insertnewpath(urltohash('GET', resp['Location'], reqopts['uri'], nil))
    when 404
      print_status "[404] Invalid link #{reqopts['uri']}"
    else
      print_status "Unhandled #{resp.code}"
    end

    sleep(datastore['SleepTime'])
  rescue StandardError => e
    print_status("Error: #{e.message}")
    vprint_status("#{$ERROR_INFO}: #{$ERROR_INFO.backtrace}")
  end

  #
  # Add new path (uri) to test non-viewed queue
  #

  def insertnewpath(hashreq)
    hashreq['uri'] = canonicalize(hashreq['uri'])

    if (hashreq['rhost'] == datastore['RHOSTS']) && (hashreq['rport'] == datastore['RPORT'])
      if !@viewed_queue.include?(hashsig(hashreq))
        if !@not_viewed_queue.read_all(hashreq).empty?
          vprint_status "Already in queue to be viewed: #{hashreq['uri']}"
        else
          vprint_status "Inserted: #{hashreq['uri']}"

          @not_viewed_queue.write(hashreq)
        end
      else
        vprint_status "#{hashreq['uri']} already visited at #{@viewed_queue[hashsig(hashreq)]}"
      end
    end
  end

  #
  # Build a new hash for a local path
  #

  def urltohash(method, url, basepath, dat)
    # method: HTTP method
    # url: uri?[query]
    # basepath: base path/uri to determine absolute path when relative
    # data: body data, nil if GET and query = uri.query

    uri = URI.parse(url)
    uritargetssl = (uri.scheme == 'https') ? true : false

    uritargethost = uri.host
    if uri.host.nil? || uri.host.empty?
      uritargethost = ctarget
      uritargetssl = cssl
    end

    uritargetport = uri.port
    if uri.port.nil?
      uritargetport = cport
    end

    uritargetpath = uri.path
    if uri.path.nil? || uri.path.empty?
      uritargetpath = '/'
    end

    newp = Pathname.new(uritargetpath)
    oldp = Pathname.new(basepath)
    if !newp.absolute?
      if oldp.to_s[-1, 1] == '/'
        newp = oldp + newp
      elsif !newp.to_s.empty?
        newp = File.join(oldp.dirname, newp)
      end
    end

    hashreq = {
      'rhost' => uritargethost,
      'rport' => uritargetport,
      'uri' => newp.to_s,
      'method' => method,
      'ctype' => 'text/plain',
      'ssl' => uritargetssl,
      'query' => uri.query,
      'data' => nil
    }

    if (method == 'GET') && !dat.nil?
      hashreq['query'] = dat
    else
      hashreq['data'] = dat
    end

    return hashreq
  end

  def canonicalize(uri)
    uri = URI(uri) unless uri.is_a?(URI)
    uri.normalize!

    path = uri.path.dup
    segments = path.split('/')
    resolved = []

    segments.each do |segment|
      next if segment == '.' || segment.empty?

      if segment == '..'
        resolved.pop unless resolved.empty?
      else
        resolved << segment
      end
    end

    uri.path = '/' + resolved.join('/')
    uri.to_s
  end

  def hashsig(hashreq)
    hashreq.to_s
  end
end

class BaseParser
  attr_accessor :crawler

  def initialize(crawler)
    self.crawler = crawler
  end

  def parse(_request, _result)
    nil
  end

  #
  # Add new path (uri) to test hash queue
  #
  def insertnewpath(hashreq)
    crawler.insertnewpath(hashreq)
  end

  def hashsig(hashreq)
    crawler.hashsig(hashreq)
  end

  def urltohash(method, url, basepath, dat)
    crawler.urltohash(method, url, basepath, dat)
  end

  def targetssl
    crawler.cssl
  end

  def targetport
    crawler.cport
  end

  def targethost
    crawler.ctarget
  end

  def targetinipath
    crawler.cinipath
  end
end
