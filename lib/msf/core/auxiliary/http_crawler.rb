# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for implementing a web crawler
#
###
module Auxiliary::HttpCrawler

  include ::Msf::Auxiliary::Report

  def initialize(info = {})
    super

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(80),
        OptString.new('VHOST', [ false, "HTTP server virtual host" ]),
        OptString.new('URI',   [ true, "The starting page to crawl", "/"]),
        Opt::Proxies,
        OptInt.new('MAX_PAGES', [ true, 'The maximum number of pages to crawl per URL', 500]),
        OptInt.new('MAX_MINUTES', [ true, 'The maximum number of minutes to spend on each URL', 5]),
        OptInt.new('MAX_THREADS', [ true, 'The maximum number of concurrent requests', 4]),
        OptString.new('HttpUsername', [false, 'The HTTP username to specify for authentication']),
        OptString.new('HttpPassword', [false, 'The HTTP password to specify for authentication']),
        OptString.new('DOMAIN', [ true, 'The domain to use for windows authentication', 'WORKSTATION']),
        OptBool.new('SSL', [ false, 'Negotiate SSL/TLS for outgoing connections', false])

      ], self.class
    )

    register_advanced_options(
      [
        OptBool.new('DirBust', [ false, 'Bruteforce common URL paths', true]),
        OptInt.new('RequestTimeout', [false, 'The maximum number of seconds to wait for a reply', 15]),
        OptInt.new('RedirectLimit', [false, 'The maximum number of redirects for a single request', 5]),
        OptInt.new('RetryLimit', [false, 'The maximum number of attempts for a single request', 5]),
        OptString.new('UserAgent', [true, 'The User-Agent header to use for all requests',
          "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ]),
        OptString.new('BasicAuthUser', [false, 'The HTTP username to specify for basic authentication']),
        OptString.new('BasicAuthPass', [false, 'The HTTP password to specify for basic authentication']),
        OptString.new('HTTPAdditionalHeaders', [false, "A list of additional headers to send (separated by \\x01)"]),
        OptString.new('HTTPCookie', [false, "A HTTP cookie header to send with each request"]),
        Opt::SSLVersion
      ], self.class
    )

    register_autofilter_ports([ 80, 8080, 443, 8000, 8888, 8880, 8008, 3000, 8443 ])
    register_autofilter_services(%W{ http https })

    begin
      require 'anemone'
      @anemone_loaded = true
    rescue ::Exception => e
      @anemone_loaded = false
      @anemone_error  = e
    end
  end

  def setup
    raise RuntimeError, "Could not load Anemone/Nokogiri: #{@anemone_error}" if not @anemone_loaded
    super
  end

  def cleanup
    if @crawler
      @crawler.shutdown rescue nil
      @crawler = nil
    end
    super
  end

  ##
  #
  # Crawler methods and accessors
  #
  ##

  # A target object for tracking URLs
  class WebTarget < ::Hash
    def to_url
      proto = self[:ssl] ? "https" : "http"
      host = self[:vhost] ? self[:vhost] : self[:host]
      if Rex::Socket.is_ipv6?(host)
        host = "[#{host}]"
      end
      "#{proto}://#{host}:#{self[:port]}#{self[:path]}"
    end
  end

  # A custom error to signify we hit the page request cap
  class MaximumPageCount < ::RuntimeError
  end

  # Some accessors for stat tracking
  attr_accessor :targets
  attr_accessor :url_count, :url_total, :form_count, :request_count


  # Entry point for the crawler code
  def run

    self.request_count = 0
    self.form_count  = 0
    self.url_count   = 0
    self.url_total   = 1

    path,query = datastore['URI'].split('?', 2)
    query ||= ""

    t = WebTarget.new

    t.merge!({
      :vhost    => vhost,
      :host     => rhost,
      :port     => rport,
      :ssl      => ssl,
      :path     => path,
      :query    => query,
      :info     => ""
    })

    if datastore['HttpUsername'] and datastore['HttpUsername'] != ''
      t[:username] = datastore['HttpUsername'].to_s
      t[:password] = datastore['HttpPassword'].to_s
      t[:domain]   = datastore['DOMAIN'].to_s
    end

    if datastore['HTTPCookie']
      t[:cookies] = {}
      datastore['HTTPCookie'].to_s.split(';').each do |pair|
        k,v = pair.strip.split('=', 2)
        next if not v
        t[:cookies][k] = v
      end
    end

    if datastore['HTTPAdditionalHeaders']
      t[:headers] = datastore['HTTPAdditionalHeaders'].to_s.split("\x01").select{|x| x.to_s.length > 0}
    end

    t[:site] = report_web_site(:wait => true, :host => t[:host], :port => t[:port], :vhost => t[:vhost], :ssl => t[:ssl])

    print_status("Crawling #{t.to_url}...")

    begin
      @current_vhost = t[:vhost]
      @current_site  = t[:site]
      ::Timeout.timeout(max_crawl_time) { crawl_target(t) }
    rescue ::Timeout::Error
      print_error("Crawl of #{t.to_url} has reached the configured timeout")
    ensure
      @current_vhost = nil
    end
    print_status("Crawl of #{t.to_url} complete")
  end

  def get_connection_timeout
    datastore['RequestTimeout']
  end

  def max_page_count
    datastore['MAX_PAGES']
  end

  def max_crawl_time
    datastore['MAX_MINUTES'] * 60.0
  end

  def max_crawl_threads
    datastore['MAX_THREADS']
  end

  def dirbust?
    datastore['DirBust']
  end

  # Scrub links that end in these extensions. If more or less is
  # desired by a particular module, this should get redefined.
  def get_link_filter
    /\.(js|png|jpe?g|bmp|gif|swf|jar|zip|gz|bz2|rar|pdf|docx?|pptx?)$/i
  end

  def focus_crawl(page)
    page.links
  end

  def crawl_target(t)
    cnt  = 0
    opts = crawler_options(t)
    url  = t.to_url

    @crawler = ::Anemone::Core.new([url], opts)
    @crawler.on_every_page do |page|
      cnt += 1

      self.request_count += 1

      # Extract any interesting data from the page
      crawler_process_page(t, page, cnt)

      # Blow up if we hit our maximum page count
      if cnt >= max_page_count
        print_error("Maximum page count reached for #{url}")
        raise MaximumPageCount, "Maximum page count reached"
      end
    end

    # Skip link processing based on a regular expression
    @crawler.skip_links_like(
      get_link_filter
    )

    # Focus our crawling on interesting, but not over-crawled links
    @crawler.focus_crawl do |page|
      focus_crawl(page)
    end

    begin
      @crawler.run
    rescue MaximumPageCount
      # No need to print anything else
    rescue ::Timeout::Error
      # Bubble this up to the top-level handler
      raise $!
    rescue ::Exception => e
      # Ridiculous f'ing anonymous timeout exception which I've no idea
      # how it comes into existence.
      if e.to_s =~ /execution expired/
        raise ::Timeout::Error
      else
        print_error("Crawler Exception: #{url} #{e} #{e.backtrace}")
      end
    ensure
      @crawler.shutdown rescue nil
      @crawler = nil
    end
  end

  # Specific module implementations should redefine this method
  # with whatever is meaningful to them.
  def crawler_process_page(t, page, cnt)
    msg = "[#{"%.5d" % cnt}/#{"%.5d" % max_page_count}]    #{page.code || "ERR"} - #{@current_site.vhost} - #{page.url}"
    case page.code
      when 301,302
        if page.headers and page.headers["location"]
          print_status(msg + " -> " + page.headers["location"].to_s)
        else
          print_status(msg)
        end
      when 500...599
        # XXX: Log the fact that we hit an error page
        print_good(msg)
      when 401,403
        print_good(msg)
      when 200
        print_status(msg)
      when 404
        print_error(msg)
      else
        print_error(msg)
    end
  end

  def crawler_options(t)
    opts = {}
    opts[:user_agent]      = datastore['UserAgent']
    opts[:verbose]         = false
    opts[:threads]         = max_crawl_threads
    opts[:obey_robots_txt] = false
    opts[:redirect_limit]  = datastore['RedirectLimit']
    opts[:retry_limit]     = datastore['RetryLimit']
    opts[:accept_cookies]  = true
    opts[:depth_limit]     = false
    opts[:skip_query_strings]  = false
    opts[:discard_page_bodies] = true
    opts[:framework]           = framework
    opts[:module]              = self
    opts[:timeout]             = get_connection_timeout
    opts[:dirbust]             = dirbust?

    if (t[:headers] and t[:headers].length > 0)
      opts[:inject_headers] = t[:headers]
    end

    if t[:cookies]
      opts[:cookies] = t[:cookies]
    end

    opts[:username] = t[:username] || ''
    opts[:password] = t[:password] || ''
    opts[:domain]   = t[:domain]   || 'WORKSTATION'

    opts
  end


  ##
  #
  # Wrappers for getters
  #
  ##

  #
  # Returns the target host
  #
  def rhost
    datastore['RHOST']
  end

  #
  # Returns the remote port
  #
  def rport
    datastore['RPORT']
  end

  #
  # Returns the VHOST of the HTTP server.
  #
  def vhost
    datastore['VHOST'] || datastore['RHOST']
  end

  #
  # Returns the boolean indicating SSL
  #
  def ssl
    ((datastore.default?('SSL') and rport.to_i == 443) or datastore['SSL'])
  end

  #
  # Returns the string indicating SSL version
  #
  def ssl_version
    datastore['SSLVersion']
  end

  #
  # Returns the configured proxy list
  #
  def proxies
    datastore['Proxies']
  end


end
end
