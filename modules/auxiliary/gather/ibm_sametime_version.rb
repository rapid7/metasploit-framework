##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'uri'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  URLS = [
      '/stmeetings/about.jsp',
      '/stmeetings/serverversion.properties',
      '/rtc/buildinfo.txt',
      '/stmeetings/configuration?format=json&verbose=true'
  ]

  PROXY_URLS = [
      '/stwebclient/i18nStrings.jsp',
      '/stwebclient/communityserver',
      '/stwebav/WebAVServlet?Name=WebPlayerVersion'
  ]

  JSON_KEYS = [
    'communityRef',
    'anonymousEnabled',
    'calinteg.enabled',
    'docshare.fileio.codebase',
    'docshare.native.codebase',
    'docshare.remote.url',
    'meetingroom.allowGuestAccess',
    'meetingroomcenter.allowGuestAccess',
    'meetingroomcenter.customLoginPage',
    'meetingroomcenter.enforceCSRFToken',
    'meetingroomcenter.enforceHiddenRooms',
    'meetingroomcenter.passwords',
    'meetingserver.statistics.jmx.enabled',
    'rtc4web.enforceNonce',
    'userInfoRedirect',
    'userInfoUrlTemplate',
    'meetingroomcenter.stProxyAddress',
    'meetingroomcenter.stProxySSLAddress'
  ]

  INFO_REGEXS = [
    # section, key, regex
    [ 'version', 'sametimeVersion', /lotusBuild">Release (.+?)<\/td>/i ],
    [ 'api', 'meeting',  /^meeting=(.*)$/i ],
    [ 'api', 'appshare', /^appshare=(.*)$/i ],
    [ 'api', 'docshare', /^docshare=(.*)$/i ],
    [ 'api', 'rtc4web', /^rtc4web=(.*)$/i ],
    [ 'api', 'roomapi', /^roomapi=(.*)$/i ],
    [ 'api', 'recordings', /^recordings=(.*)$/i ],
    [ 'api', 'audio', /^audio=(.*)$/i ],
    [ 'api', 'video', /^video=(.*)$/i]
  ]


  def initialize
    super(
      'Name'    => 'IBM Lotus Sametime Version Enumeration',
      'Description' => %q{
        This module scans an IBM Lotus Sametime web interface to enumerate
        the version and configuration information.
      },
      'Author'     =>
        [
          'kicks4kittens' # Metasploit module
        ],
      'License'   => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The path to the Sametime Server", '/']),
        OptBool.new('QuerySametimeProxy', [ true,  "Automatically query Sametime proxy if found", true]),
        OptBool.new('ShowVersions', [ true,  "Display Version information from server", true]),
        OptBool.new('ShowConfig', [ true,  "Display Config information from server", true]),
        OptBool.new('ShowAPIVersions', [ true,  "Display API Version information from server", false])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('StoreConfigs', [ true,  "Store JSON configs to loot", true])
      ], self.class)

  end

  def check_url(url, proxy='')

    cgi_options = {
      'uri' => normalize_uri(target_path, url),
      'method' => 'GET'
    }

    if proxy.empty?
      checked_host = datastore['RHOST']
    else
      checked_host = proxy
      cgi_options.merge!({
        'rhost' => proxy, # connect to Sametime Proxy
        'vhost' => proxy  # set appropriate VHOST
      })
    end

    vprint_status("Requesting \"#{checked_host}:#{rport}#{normalize_uri(target_uri.path, url)}\"")
    res = send_request_cgi(cgi_options)

    if res.nil?
      print_status("#{checked_host}:#{rport} - Did not respond")
      return
    elsif res.code == 403
      print_status("#{checked_host}:#{rport} - Access Denied #{res.code} #{res.message}")
      return
    elsif res.code != 200
      print_error("#{checked_host}:#{rport} - Unexpected Response code (#{res.code}) received from server")
      return
    end

    if url.include?('WebAVServlet')
      # special handler for WebAVServlet as body is JSON regardless of content-type
      begin
        res_json = JSON.parse(res.body)
      rescue JSON::ParserError
        print_error("Unable to parse JSON response")
      end
      extract_webavservlet_data(res_json)
    elsif res['content-type'].include?("text/plain") or res['content-type'].include?("text/html")
      extract_data(body, url)
    elsif res['content-type'].include?("text/json") or res['content-type'].include?("text/javaScript")
      begin
        res_json = JSON.parse(res.body)
      rescue JSON::ParserError
        print_error("Unable to parse JSON response")
      end
      # store configuration files as loot
      store_config(url, res_json, checked_host) if datastore['StoreConfigs']
      extract_json_data(res_json)
    end
  end

  # extract data from WebAVServlet
  def extract_webavservlet_data(res_json)
    # stwebav/WebAVServlet --> WebPlayer information
    if res_json['Softphone']
      @version_info['version']['Softphone'] = res_json['Softphone']
    end

    if res_json['WebPlayer']
      @version_info['version']['WebPlayer'] = res_json['WebPlayer']
    end
  end

  def extract_data(data, url)
    # extract data from response
    INFO_REGEXS.each do |regex|
      if data =~ regex[2]
        @version_info[regex[0]][regex[1]] = $1.chomp
      end
    end

    if url.include?('buildinfo.txt') and data =~ /^(\d{8}-\d+)$/
      @version_info['version']['buildinfo'] = $1.chomp
    end

    if data =~ /aboutBoxProductTitle":"(.*?)",/i
      @version_info['version']['sametimeVersion'] = $1.chomp unless @version_info['version']['sametimeVersion']
    end
  end

  # extract data from JSON response
  def extract_json_data(json)
    JSON_KEYS.each do |k|
      @version_info['conf'][k] = json[k] if json[k]
    end
  end

  def report
    if @version_info['version']['sametimeVersion']
      print_line
      print_good("#{@version_info['version']['sametimeVersion']} Detected (#{peer})")
    else
      print_line
      print_status("#{peer} - IBM Lotus Sametime information")
    end

    # configure tables
    version_tbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "IBM Lotus Sametime Information [Version]",
      'Prefix'  => "",
      'Indent'  => 1,
      'Columns'   =>
      [
        "Component",
        "Version"
      ])

    conf_tbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "IBM Lotus Sametime Information [Config]",
      'Prefix'  => "",
      'Indent'  => 1,
      'Columns'   =>
      [
        "Key",
        "Value"
      ])

    api_tbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header'  => "IBM Lotus Sametime Information [API]",
      'Prefix'  => "",
      'Indent'  => 1,
      'Columns'   =>
      [
        "API",
        "Version"
      ])

    # populate tables
    @version_info['version'].each do | line |
      version_tbl << [ line[0], line[1] ]
    end

    @version_info['conf'].each do | line |
      conf_tbl << [ line[0], line[1] ]
    end

    @version_info['api'].each do | line |
      api_tbl << [ line[0], line[1] ]
    end

    # display tables
    print_good("#{version_tbl.to_s}") if not version_tbl.to_s.empty? and datastore['ShowVersions']
    print_good("#{api_tbl.to_s}") if not api_tbl.to_s.empty? and datastore['ShowAPIVersions']
    print_good("#{conf_tbl.to_s}") if not conf_tbl.to_s.empty? and datastore['ShowConfig']

    # report_note
    report_note(
      :host  => rhost,
      :port  => rport,
      :proto => 'http',
      :ntype => 'ibm_lotus_sametime_version',
      :data  => @version_info['version']['sametimeVersion']
    ) if @version_info['version']['sametimeVersion']
  end

  def store_config(url, config_to_store, checked_host)
    # store configuration as loot
    unless config_to_store.empty?
      loot = store_loot(
        "ibm_lotus_sametime_configuration_" + url,
        "text/json",
        datastore['rhost'],
        config_to_store,
        ".json"
      )
      print_good("#{checked_host} - IBM Lotus Sametime Configuration data stored as loot")
      print_status("#{checked_host}#{normalize_uri(target_uri.path, url)}\n => #{loot}")
    end
  end

  def target_path
    normalize_uri(target_uri.path)
  end

  def proxy?
    @version_info['conf']['meetingroomcenter.stProxyAddress'] or @version_info['conf']['meetingroomcenter.stProxySSLAddress']
  end

  def use_proxy?
    datastore['QuerySametimeProxy']
  end

  def proxy_ssl?
    @version_info['conf']['meetingroomcenter.stProxySSLAddress']
  end

  def run
    # create storage for extracted information+
    @version_info = {}
    @version_info['version'] = {}
    @version_info['conf'] = {}
    @version_info['api'] = {}

    print_status("#{peer} - Checking IBM Lotus Sametime Server")
    URLS.each do | url |
      check_url(url)
    end

    if proxy? and use_proxy?
      # check Sametime proxy if configured to do so
      if proxy_ssl? and ssl
        # keep using SSL
        proxy = URI(@version_info['conf']['meetingroomcenter.stProxySSLAddress']).host
        vprint_status("Testing discovered Sametime proxy address for further data #{proxy}")
      else
        proxy = URI(@version_info['conf']['meetingroomcenter.stProxyAddress']).host
        vprint_status("Testing discovered Sametime proxy address for further data #{proxy}")
      end

      print_good("#{peer} - Sametime Proxy address discovered #{proxy}")

      PROXY_URLS.each do | url |
        check_url(url, proxy)
      end
    elsif proxy?
      print_status("#{peer} - Sametime Proxy address discovered, but checks disabled")
    end

    report unless @version_info.empty?
  end

end
