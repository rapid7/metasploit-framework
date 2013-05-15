require 'msf/core/exploit/http/proxy'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpServer::Proxy

  def initialize
    super(
      'Name'        => 'HTTP Proxy',
      'Description' => %q{
        This module creates an HTTP proxy using Rex' HTTP modules.
        Requests follow the switchboard through configured upstream proxies
        and pivots. This module is responsible for performing work on  the
        requests and responses passing through the proxy.
        This PoC implementation allows MITM and logging. Setting RPORT and RHOST
        configures the proxy to forward to a single host. Leaving these options
        blank will pass requests to the original target.
        The underlying proxy service can operate as a standard or transparent
        HTTP proxy, rewriting proxy request headers as needed.
      },
      'Author'      => 'RageLtMan <rageltman[at]sempervictus>',
      'License'     => MSF_LICENSE,
    )

    # Clients make requests to all UIRs
    deregister_options('URI')

    register_options(
      [
        OptString.new('SUBSTITUTIONS', [
          false,
          'Response subs in gsub format - original,sub;original,sub. Regex supported.'
        ]),
        OptBool.new('HTTP::proxy::MITM::request', [false, 'MITM requests with substitutions']),
        OptBool.new('HTTP::proxy::MITM::response', [false, 'MITM responses with substitutions']),
        OptBool.new('HTTP::proxy::MITM::headers', [false, 'MITM headers with substitutions']),
        OptBool.new('HTTP::proxy::report', [false, 'Report sites and pages']),
      ])

  end

  # Do stuff with responses
  def proxy_action_response(cli,res)
    vprint_good "\nClient's (#{cli.peerhost}:#{cli.peerport}:) original response:\n#{res.to_s}"
    if datastore['HTTP::proxy::MITM::response']
      make_subs(res) if datastore['SUBSTITUTIONS']
    end
    if datastore['HTTP::proxy::report'] and ([200,401,403] + (500..599).to_a).include?(res.code)
      log_response(cli,res)
    end
  end

  # Do stuff with requests
  def proxy_action_request(cli,req)
    vprint_good "\nClient #{cli.peerhost}:#{cli.peerport} requested:\n#{req.to_s}"
    if datastore['HTTP::proxy::MITM::request']
      make_subs(req) if datastore['SUBSTITUTIONS']
    end
  end


  def run
    @substitutions = process_subs(datastore['SUBSTITUTIONS'])
    exploit
  end


  # Borrows heavily from crawler.rb to log web sites and pages
  # based on client request and response instead of Anemone's page
  # class. This wont work unless the client request is still valid
  def log_response(cli,res)
    return unless cli.request
    t = Msf::Auxiliary::HttpCrawler::WebTarget.new

    # Build site report information
    cli.request.headers.map do |k,v|
      t[k.downcase.intern] = v
    end if cli.request

    t[:port] ||= t[:ssl] ? 443 : 80
    t[:site] = report_web_site(:wait => true, :host => t[:host], :port => t[:port], :vhost => t[:vhost], :ssl => t[:ssl])

    # Build page report information, from crawler.rb
    info = {
      :web_site => t[:site],
      :path     => cli.request.uri,
      :query    => cli.request.param_string,
      :code     => res.code,
      :body     => res.body,
      :headers  => res.headers,
      :cookie   => cli.request.headers['cookie']
    }

    if res.headers['content-type']
      info[:ctype] = res.headers['content-type']
    end

    if res.get_cookies and not res.get_cookies.empty?
      info[:cookie] = res.get_cookies
    end

    if res.headers['authorization']
      info[:auth] = res.headers['authorization']
    end

    if res.headers['location']
      info[:location] = res.headers['location']
    end

    if res.headers['last-modified']
      info[:mtime] = res.headers['last-modified']
    end

    report_web_page(info) unless res.code == 404
  end

  # Run substitution sets through response
  def make_subs(resp)
    @substitutions.each do |sub_set|
      resp.body.gsub!(sub_set[0],sub_set[1])
      if datastore['HTTP::proxy::MITM::headers']
        # In-place alteration of hashes during iteration can be bad
        hdr_dup = resp.headers.dup
        hdr_dup.each do |key, val|
          resp.headers[key] = val.to_s.gsub(sub_set[0],sub_set[1]) if val
        end
      end
    end
  end

  # Convert substitution definition strings to gsub compatible format
  def process_subs(subs = nil)
    return [] if subs.nil? or subs.empty?
    new_subs = []
    subs.split(';').each do |substitutions|
      new_subs << substitutions.split(',', 2).map do |sub|
        if sub.scan(/\/.*\//).empty?
          sub
        else
          sub = Regexp.new(sub[1..-2])
        end
      end
    end
    return new_subs
  end
end
