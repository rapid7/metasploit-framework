##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'uri'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

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

  def check_url(tpath, url, stproxy_rhost='')

    if stproxy_rhost.empty?
      checked_host = datastore['RHOST']
      vprint_status("Requesting \"#{checked_host}:#{rport}#{normalize_uri(tpath, url)}\"")
      res = send_request_cgi({
        'uri' => normalize_uri(tpath, url),
        'method' => 'GET'
      })
    else
      checked_host = stproxy_rhost
      # make request with provided stproxy rhost
      vprint_status("Requesting \"#{checked_host}:#{rport}#{normalize_uri(tpath, url)}\"")
      res = send_request_cgi({
        'uri' => normalize_uri(tpath, url),
        'method' => 'GET',
        'rhost' => stproxy_rhost, # connect to Sametime Proxy
        'vhost' => stproxy_rhost # set appropriate VHOST
      })
    end

    if not res
      print_status("#{checked_host}:#{rport} - Did not respond")
      return
    elsif res.code == 403
      print_status("#{checked_host}:#{rport} - Access Denied #{res.code} #{res.message}")
      return
    elsif not res.code == 200
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

      res.body.each_line do | response_line |
        extract_response_data(response_line, url)
      end

    elsif res['content-type'].include?("text/json") or res['content-type'].include?("text/javaScript")

      begin
        res_json = JSON.parse(res.body)
      rescue JSON::ParserError
        print_error("Unable to parse JSON response")
      end

      # store configuration files as loot
      store_config(tpath, url, res_json, checked_host) if datastore['StoreConfigs']

      extract_json_data(res_json)

    end

  end

  def extract_webavservlet_data(res_json)
    # extract data from WebAVServlet

    # stwebav/WebAVServlet --> WebPlayer information
    if res_json['Softphone']
      @version_info['version']['Softphone'] = res_json['Softphone']
    end
    if res_json['WebPlayer']
      @version_info['version']['WebPlayer'] = res_json['WebPlayer']
    end

  end

  def extract_response_data(response_line, url)
    # extract data from response

    case response_line
    # stmeetings/about.jsp --> Sametime Server version string
    when /lotusBuild">Release (.+?)<\/td>/i
      # lotus build version
      @version_info['version']['sametimeVersion'] = $1.chomp
    # serverversion.properties --> API Version information
    when /^meeting=(.*)$/i
      # meeting api version
      @version_info['api']['meeting'] = $1.chomp
    when /^appshare=(.*)$/i
      # appshare api version
      @version_info['api']['appshare'] = $1.chomp
    when /^docshare=(.*)$/i
      # docshare api version
      @version_info['api']['docshare'] = $1.chomp
    when /^rtc4web=(.*)$/i
      # rtc4web api version
      @version_info['api']['rtc4web'] = $1.chomp
    when /^roomapi=(.*)$/i
      # room api version
      @version_info['api']['roomapi'] = $1.chomp
    when /^recordings=(.*)$/i
      # recording api version
      @version_info['api']['recordings'] = $1.chomp
    when /^audio=(.*)$/i
      # audio api version
      @version_info['api']['audio'] = $1.chomp
    when /^video=(.*)$/i
      # video api version
      @version_info['api']['video'] = $1.chomp
    # rtc/buildinfo.txt --> Server Build version
    when /^(\d{8}-\d+)$/
      if url.include?('buildinfo.txt')
        # buildinfo version
        @version_info['version']['buildinfo'] = $1.chomp
      end
    # stwebclient/i18nStrings.jsp --> Sametime Server version string
    when /aboutBoxProductTitle":"(.*?)",/i
      if not @version_info['version']['sametimeVersion']
        # sametime version
        @version_info['version']['sametimeVersion'] = $1.chomp
      end
    end
  end


  def extract_json_data(res_json)
    # extract data from JSON response

    # stwebclient/communityserver --> Community server address
    if res_json['communityRef']
      @version_info['conf']['communityRef'] = res_json['communityRef']
    end
    if res_json['anonymousEnabled']
      @version_info['conf']['communityref_anonymousEnabled'] = res_json['anonymousEnabled']
    # stmeetings/configuration --> Sametime configuration
    end
    if res_json['calinteg.enabled']
      @version_info['conf']['calinteg.enabled'] = res_json['calinteg.enabled']
    end
    if res_json['docshare.fileio.codebase']
      @version_info['conf']['docshare.fileio.codebase'] = res_json['docshare.fileio.codebase']
    end
    if res_json['docshare.native.codebase']
      @version_info['conf']['docshare.native.codebase'] = res_json['docshare.native.codebase']
    end
    if res_json['docshare.remote.url']
      @version_info['conf']['docshare.remote.url'] = res_json['docshare.remote.url']
    end
    if res_json['meetingroom.allowGuestAccess']
      if res_json['meetingroom.allowGuestAccess'] == "1"
        @version_info['conf']['meetingroom.allowGuestAccess'] = "true"
      else
        @version_info['conf']['meetingroom.allowGuestAccess'] = "false"
      end
    end
    if res_json['meetingroomcenter.allowGuestAccess']
      if res_json['meetingroomcenter.allowGuestAccess'] == "1"
        @version_info['conf']['meetingroomcenter.allowGuestAccess'] = "true"
      else
        @version_info['conf']['meetingroomcenter.allowGuestAccess'] = "false"
      end
    end
    if res_json['meetingroomcenter.customLoginPage']
      @version_info['conf']['meetingroomcenter.customLoginPage'] = res_json['meetingroomcenter.customLoginPage']
    end
    if res_json['meetingroomcenter.enforceCSRFToken']
      @version_info['conf']['meetingroomcenter.enforceCSRFToken'] = res_json['meetingroomcenter.enforceCSRFToken']
    end
    if res_json['meetingroomcenter.enforceHiddenRooms']
      @version_info['conf']['meetingroomcenter.enforceHiddenRooms'] = res_json['meetingroomcenter.enforceHiddenRooms']
    end
    if res_json['meetingroomcenter.passwords']
      @version_info['conf']['meetingroomcenter.passwords'] = res_json['meetingroomcenter.passwords']
    end
    if res_json['meetingserver.statistics.jmx.enabled']
      @version_info['conf']['meetingserver.statistics.jmx.enabled'] = res_json['meetingserver.statistics.jmx.enabled']
    end
    if res_json['rtc4web.enforceNonce']
      @version_info['conf']['rtc4web.enforceNonce'] = res_json['rtc4web.enforceNonce']
    end
    if res_json['userInfoRedirect']
      @version_info['conf']['userInfoRedirect'] = res_json['userInfoRedirect']
    end
    if res_json['userInfoUrlTemplate']
      @version_info['conf']['userInfoUrlTemplatee'] = res_json['userInfoUrlTemplate']
    end
    if res_json['meetingroomcenter.stProxyAddress']
      @version_info['conf']['meetingroomcenter.stProxyAddress'] = res_json['meetingroomcenter.stProxyAddress']
    end
    if res_json['meetingroomcenter.stProxySSLAddress']
      @version_info['conf']['meetingroomcenter.stProxySSLAddress'] = res_json['meetingroomcenter.stProxySSLAddress']
    end
    # stwebclient/communityserver --> Sametime Community server name
    if res_json['communityRef']
      @version_info['conf']['communityRef'] = res_json['communityRef']
      @version_info['conf']['anonymousEnabled'] = res_json['anonymousEnabled']
    end

  end

  def report

    if @version_info['version']['sametimeVersion']
      print_line()
      print_good("#{@version_info['version']['sametimeVersion']} Detected (#{peer})")
    else
      print_line()
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
    if @version_info['version']['sametimeVersion']
      report_note(
        :host  => datastore['rhost'],
        :port  => datastore['rport'],
        :proto => 'http',
        :ntype => 'ibm_lotus_sametime_version',
        :data  => @version_info['version']['sametimeVersion']
      )
    end
  end

  def store_config(tpath, url, config_to_store, checked_host)
    # store configuration as loot

    if not config_to_store.empty?
      loot = store_loot(
        "ibm_lotus_sametime_configuration_" + url,
        "text/json",
        datastore['rhost'],
        config_to_store,
        ".json"
      )

    print_good("#{checked_host} - IBM Lotus Sametime Configuration data stored as loot")
    print_status("#{checked_host}#{normalize_uri(tpath, url)}\n => #{loot}")
    end
  end

  def run

    # create storage for extracted information+
    @version_info = {}
    @version_info['version'] = {}
    @version_info['conf'] = {}
    @version_info['api'] = {}

    tpath = normalize_uri(target_uri.path)

    sametime_urls = [
      '/stmeetings/about.jsp',
      '/stmeetings/serverversion.properties',
      '/rtc/buildinfo.txt',
      '/stmeetings/configuration?format=json&verbose=true'
    ]

    sametime_proxy_urls = [
      '/stwebclient/i18nStrings.jsp',
      '/stwebclient/communityserver',
      '/stwebav/WebAVServlet?Name=WebPlayerVersion'
    ]

    print_status("#{peer} - Checking IBM Lotus Sametime Server")
    sametime_urls.each do | url |
      check_url(tpath, url)
    end

    if @version_info['conf']['meetingroomcenter.stProxyAddress'] or @version_info['conf']['meetingroomcenter.stProxySSLAddress']
      # check Sametime proxy if configured to do so
      if datastore['QuerySametimeProxy']

        if @version_info['conf']['meetingroomcenter.stProxySSLAddress'] and datastore['SSL']
          # keep using SSL
          stproxy_rhost = URI(@version_info['conf']['meetingroomcenter.stProxySSLAddress']).host
          vprint_status("Testing discovered Sametime proxy address for further data #{stproxy_rhost}")
        else
          stproxy_rhost = URI(@version_info['conf']['meetingroomcenter.stProxyAddress']).host
          vprint_status("Testing discovered Sametime proxy address for further data #{stproxy_rhost}")
        end

        print_good("#{peer} - Sametime Proxy address discovered #{stproxy_rhost}")

        sametime_proxy_urls.each do | url |
          check_url(tpath, url, stproxy_rhost)
        end

      else
        print_status("#{peer} - Sametime Proxy address discovered #{stproxy_rhost}, but checks disabled")
      end
    end

    report unless @version_info.empty?

  end

end
