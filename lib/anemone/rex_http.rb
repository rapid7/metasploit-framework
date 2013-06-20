require 'rex'
require 'anemone/page'
require 'anemone/cookie_store'


#
# This is an alternate Anemone::HTTP implementation that uses the Metasploit Rex
# library and the Rex::Proto::Http protocol stack.
#

module Anemone
  class HTTP
    # Maximum number of redirects to follow on each get_response
    # REDIRECT_LIMIT = 5

    # CookieStore for this HTTP client
    attr_reader :cookie_store

    def initialize(opts = {})
      @connections = {}
      @opts = opts
      @cookie_store = CookieStore.new(@opts[:cookies])
    end

    #
    # Fetch a single Page from the response of an HTTP request to *url*.
    # Just gets the final destination page.
    #
    def fetch_page(url, referer = nil, depth = nil)
      fetch_pages(url, referer, depth).last
    end

    #
    # Create new Pages from the response of an HTTP request to *url*,
    # including redirects
    #
    def fetch_pages(url, referer = nil, depth = nil)
      begin
        url = URI(url) unless url.is_a?(URI)
        pages = []
        get(url, referer) do |response, code, location, redirect_to, response_time|

          page = Page.new(location, :body => response.body.dup,
                                      :code => code,
                                      :headers => response.headers,
                                      :referer => referer,
                                      :depth => depth,
                                      :redirect_to => redirect_to,
                                      :response_time => response_time,
                                      :dirbust => @opts[:dirbust]
          )
          # Store the associated raw HTTP request
          page.request = response.request
		  pages << page
        end

        return pages
      rescue => e
        if verbose?
          puts e.inspect
          puts e.backtrace
        end
        return [Page.new(url, :error => e)]
      end
    end

    #
    # The maximum number of redirects to follow
    #
    def redirect_limit
      @opts[:redirect_limit] || REDIRECT_LIMIT
    end

    #
    # The user-agent string which will be sent with each request,
    # or nil if no such option is set
    #
    def user_agent
      @opts[:user_agent]
    end

    #
    # The virtual host to override the host header with, per url
    # TODO: implement
    #
    def virtual_host(url)
      url.host
    end

    #
    # Does this HTTP client accept cookies from the server?
    #
    def accept_cookies?
      @opts[:accept_cookies]
    end

    private

    #
    # Retrieve HTTP responses for *url*, including redirects.
    # Yields the response object, response code, and URI location
    # for each response.
    #
    def get(url, referer = nil)
      limit = redirect_limit
      loc = url
      begin
          # if redirected to a relative url, merge it with the host of the original
          # request url
          loc = url.merge(loc) if loc.relative?

          response, response_time = get_response(loc, referer)
          code = response.code.to_i

          redirect_to = nil
          if code >= 300 and code <= 310
          	redirect_to = URI(response['location']).normalize
          end

          yield response, code, loc, redirect_to, response_time


          limit -= 1
      end while (loc = redirect_to) && allowed?(redirect_to, url) && limit > 0
    end

    #
    # Get an HTTPResponse for *url*, sending the appropriate User-Agent string
    #
    # MODIFIED: Change get_response to allow fine tuning of the HTTP request before
    #           it is sent to the remote system.
    #
    def get_response(url, referer = nil)
      opts = {
      	'uri'   => url.path,
        'query' => url.query
      }

      opts['agent']   = user_agent if user_agent
      opts['cookie']  = @cookie_store.to_s unless @cookie_store.empty? || (!accept_cookies? && @opts[:cookies].nil?)

      head = {}
      if referer
      	head['Referer'] = referer.to_s
      end

      if @opts[:http_basic_auth]
      	head['Authorization'] = "Basic " + @opts[:http_basic_auth]
      end

      @opts[:inject_headers].each do |hdr|
      	k,v = hdr.split(':', 2)
      	head[k] = v
      end

      opts['headers'] = head

      retries = 0
      begin
        start = Time.now()

        response = nil
        request  = nil
        begin
			conn     = connection(url)
			request  = conn.request_raw(opts)
			response = conn.send_recv(request, @opts[:timeout] || 10 )
		rescue ::Errno::EPIPE, ::Timeout::Error
		end

        finish = Time.now()

        response_time = ((finish - start) * 1000).round
        @cookie_store.merge!(response['Set-Cookie']) if accept_cookies?
        return response, response_time
      rescue EOFError
        retries += 1
        retry unless retries > (@opts[:retry_limit] || 3)
      end
    end

    def connection(url)
		context =  { }
		context['Msf']        = @opts[:framework] if @opts[:framework]
		context['MsfExploit'] = @opts[:module] if @opts[:module]

		conn = Rex::Proto::Http::Client.new(
			url.host,
			url.port.to_i,
			context,
			url.scheme == "https",
			'SSLv23',
			@opts[:proxies],
                    @opts[:username],
                    @opts[:password]
		)

		conn.set_config(
			'vhost'      => virtual_host(url),
			'agent'      => user_agent,
      'domain'     => @opts[:domain]
		)

		conn
    end

    def verbose?
      @opts[:verbose]
    end

    #
    # Allowed to connect to the requested url?
    #
    def allowed?(to_url, from_url)
      to_url.host.nil? || (to_url.host == from_url.host)
    end

  end
end
