#
# The Nexpose API
#
=begin

Copyright (C) 2009-2012, Rapid7 LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    * Neither the name of Rapid7 LLC nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end

#
# WARNING! This code makes an SSL connection to the Nexpose server, but does NOT
#          verify the certificate at this time. This can be a security issue if
#          an attacker is able to man-in-the-middle the connection between the
#          Metasploit console and the Nexpose server. In the common case of
#          running Nexpose and Metasploit on the same host, this is a low risk.
#

#
# WARNING! This code is still rough and going through substantive changes. While
#          you can build tools using this library today, keep in mind that method
#          names and parameters may change in the future.
#

require 'date'
require 'rexml/document'
require 'net/https'
require 'net/http'
require 'uri'
require 'rex/mime'


module Nexpose

module Sanitize
  def replace_entities(str)
    ret = str.dup
    ret.gsub!(/&/, "&amp;")
    ret.gsub!(/'/, "&apos;")
    ret.gsub!(/"/, "&quot;")
    ret.gsub!(/</, "&lt;")
    ret.gsub!(/>/, "&gt;")
    ret
  end
end

class APIError < ::RuntimeError
  attr_accessor :req, :reason
  def initialize(req, reason = '')
    self.req = req
    self.reason = reason
  end
  def to_s
    "NexposeAPI: #{self.reason}"
  end
end

class AuthenticationFailed < APIError
  def initialize(req)
    self.req = req
    self.reason = "Login Failed"
  end
end

module XMLUtils
  def parse_xml(xml)
    ::REXML::Document.new(xml.to_s)
  end
end

class APIRequest
  include XMLUtils

  attr_reader :http
  attr_reader :uri
  attr_reader :headers
  attr_reader :retry_count
  attr_reader :time_out
  attr_reader :pause

  attr_reader :req
  attr_reader :res
  attr_reader :sid
  attr_reader :success

  attr_reader :error
  attr_reader :trace

  attr_reader :raw_response
  attr_reader :raw_response_data

  def initialize(req, url)
    @url = url
    @req = req
    prepare_http_client
  end

  def prepare_http_client
    @retry_count = 0
    @retry_count_max = 10
    @time_out = 30
    @pause = 2
    @uri = URI.parse(@url)
    @http = ::Net::HTTP.new(@uri.host, @uri.port)
    @http.use_ssl = true
    #
    # XXX: This is obviously a security issue, however, we handle this at the client level by forcing
    #      a confirmation when the nexpose host is not localhost. In a perfect world, we would present
    #      the server signature before accepting it, but this requires either a direct callback inside
    #      of this module back to whatever UI, or opens a race condition between accept and attempt.
    #
    @http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    @headers = {'Content-Type' => 'text/xml'}
    @success = false
  end

  def execute
    @conn_tries = 0

    begin
    prepare_http_client

    @raw_response = @http.post(@uri.path, @req, @headers)
    @raw_response_data = @raw_response.body
    @res = parse_xml(@raw_response_data)

    if(not @res.root)
      @error = "Nexpose service returned invalid XML"
      return @sid
    end

    @sid = attributes['session-id']

    @success = true

    if(attributes['success'] and attributes['success'].to_i == 0)
      @success = false
    end

    # Look for a stack trace
    @res.elements.each('//Failure/Exception') do |s|

      # 1.1 returns lower case elements
      s.elements.each('message') do |m|
        @error = m.text
      end
      s.elements.each('stacktrace') do |m|
        @trace = m.text
      end

      # 1.2 returns capitalized elements
      s.elements.each('Message') do |m|
        @error = m.text
      end
      s.elements.each('Stacktrace') do |m|
        @trace = m.text
      end
    end

    # This is a hack to handle corner cases where a heavily loaded Nexpose instance
    # drops our HTTP connection before processing. We try 5 times to establish a
    # connection in these situations. The actual exception occurs in the Ruby
    # http library, which is why we use such generic error classes.
    rescue ::ArgumentError, ::NoMethodError
      if @conn_tries < 5
        @conn_tries += 1
        retry
      end
    rescue ::Timeout::Error
      if @conn_tries < 5
        @conn_tries += 1
        retry
      end
      @error = "Nexpose host did not respond"
    rescue ::SocketError, ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::EADDRNOTAVAIL
      @error = "Nexpose host is unreachable"
    # Handle console-level interrupts
    rescue ::Interrupt
      @error = "Received a user interrupt"
    rescue ::Errno::ECONNRESET,::Errno::ECONNREFUSED,::Errno::ENOTCONN,::Errno::ECONNABORTED, ::OpenSSL::SSL::SSLError
      @error = "Nexpose service is not available"
    rescue ::REXML::ParseException
      @error = "Nexpose has not been properly licensed"
    end

    @success = false if @error

    @sid
  end

  def attributes(*args)
    return if not @res.root
    @res.root.attributes(*args)
  end

  def self.execute(url,req)
    obj = self.new(req,url)
    obj.execute
    if(not obj.success)
      raise APIError.new(obj, "Action failed: #{obj.error}")
    end
    obj
  end

end

module NexposeAPI

  def make_xml(name, opts={}, data='')
    xml = REXML::Element.new(name)
    if(@session_id)
      xml.attributes['session-id'] = @session_id
    end

    opts.keys.each do |k|
      xml.attributes[k] = "#{opts[k]}"
    end

    xml.text = data

    xml
  end

  def make_xml_plain(name, opts={}, data='')
    xml = REXML::Element.new(name)

    opts.keys.each do |k|
      xml.attributes[k] = "#{opts[k]}"
    end

    xml.text = data

    xml
  end
  def scan_stop(param)
    r = execute(make_xml('ScanStopRequest', { 'scan-id' => param }))
    r.success
  end

  def scan_status(param)
    r = execute(make_xml('ScanStatusRequest', { 'scan-id' => param }))
    r.success ? r.attributes['status'] : nil
  end

  def scan_activity
    r = execute(make_xml('ScanActivityRequest', { }))
    if(r.success)
      res = []
      r.res.elements.each("//ScanSummary") do |scan|
        res << {
          :scan_id    => scan.attributes['scan-id'].to_i,
          :site_id    => scan.attributes['site-id'].to_i,
          :engine_id  => scan.attributes['engine-id'].to_i,
          :status     => scan.attributes['status'].to_s,
          :start_time => Date.parse(scan.attributes['startTime'].to_s).to_time
        }
      end
      return res
    else
      return false
    end
  end

  def scan_statistics(param)
    r = execute(make_xml('ScanStatisticsRequest', {'scan-id' => param }))
    if(r.success)
      res = {}
      r.res.elements.each("//ScanSummary/nodes") do |node|
        res[:nodes] = {}
        node.attributes.keys.each do |k|
          res[:nodes][k] = node.attributes[k].to_i
        end
      end
      r.res.elements.each("//ScanSummary/tasks") do |task|
        res[:task] = {}
        task.attributes.keys.each do |k|
          res[:task][k] = task.attributes[k].to_i
        end
      end
      r.res.elements.each("//ScanSummary/vulnerabilities") do |vuln|
        res[:vulns] ||= {}
        k = vuln.attributes['status'] + (vuln.attributes['severity'] ? ("-" + vuln.attributes['severity']) : '')
        res[:vulns][k] = vuln.attributes['count'].to_i
      end
      r.res.elements.each("//ScanSummary") do |summ|
        res[:summary] = {}
        summ.attributes.keys.each do |k|
          res[:summary][k] = summ.attributes[k]
          if (res[:summary][k] =~ /^\d+$/)
            res[:summary][k] = res[:summary][k].to_i
          end
        end
      end
      r.res.elements.each("//ScanSummary/message") do |message|
        res[:message] = message.text
      end
      return res
    else
      return false
    end
  end

  def report_generate(param)
    r = execute(make_xml('ReportGenerateRequest', { 'report-id' => param }))
    r.success
  end

  def report_last(param)
    r = execute(make_xml('ReportHistoryRequest', { 'reportcfg-id' => param }))
    res = nil
    if(r.success)
      stk = []
      r.res.elements.each("//ReportSummary") do |rep|
        stk << [ rep.attributes['id'].to_i, rep.attributes['report-URI'] ]
      end
      if (stk.length > 0)
        stk.sort!{|a,b| b[0] <=> a[0]}
        res = stk[0][1]
      end
    end
    res
  end

  def report_last_detail(param)
    r = execute(make_xml('ReportHistoryRequest', { 'reportcfg-id' => param }))
    res = nil
    if(r.success)
      stk = {}
      r.res.elements.each("//ReportSummary") do |rep|
        stk[ rep.attributes['id'].to_i ] = {
          'id'     => rep.attributes['id'].to_i,
          'url'    => rep.attributes['report-URI'],
          'status' => rep.attributes['status'],
          'date'   => rep.attributes['generated-on']
        }
      end
      if (stk.keys.length > 0)
        res = stk[ stk.keys.sort{|a,b| b[0] <=> a[0]}.first ]
      end
    end
    res
  end

  def report_history(param)
    execute(make_xml('ReportHistoryRequest', { 'reportcfg-id' => param }))
  end

  def report_config_delete(param)
    r = execute(make_xml('ReportDeleteRequest', { 'reportcfg-id' => param }))
    r.success
  end

  def report_delete(param)
    r = execute(make_xml('ReportDeleteRequest', { 'report-id' => param }))
    r.success
  end

  def device_delete(param)
    r = execute(make_xml('DeviceDeleteRequest', { 'device-id' => param }))
    r.success
  end

  def vuln_exception_create(vuln_id, reason, scope, comment='', attrs={})
    attrs = attrs.merge({ 'vuln-id' => vuln_id, 'reason' => reason, 'scope' => scope })
    req = make_xml('VulnerabilityExceptionCreateRequest', attrs)
 		com = make_xml_plain('comment', {}, comment.to_s)
    req << com
    r = execute(req, '1.2')
  end

  def vuln_exception_approve(exception_id, comment='', attrs={})
    attrs = attrs.merge({ 'exception-id' => exception_id })
    req = make_xml('VulnerabilityExceptionApproveRequest', attrs)
 		com = make_xml_plain('comment', {}, comment.to_s)
    req << com
    r = execute(req, '1.2')
  end

  def vuln_exception_update_expiration(exception_id, expiration_date, attrs={})
    attrs = attrs.merge({ 'exception-id' => exception_id, 'expiration-date' => expiration_date })
    req = make_xml('VulnerabilityExceptionUpdateExpirationDateRequest', attrs)
    r = execute(req, '1.2')
  end

  def asset_group_delete(connection, id, debug = false)
    r = execute(make_xml('AssetGroupDeleteRequest', { 'group-id' => param }))
    r.success
  end

  def asset_group_create(name, description, devices)
    req = make_xml('AssetGroupSaveRequest')
    req_ag = make_xml_plain('AssetGroup', { 'id' => "-1", 'name' => name, 'description' => description })
 		req_devices = make_xml_plain('Devices')
    devices.each do |did|
      req_devices << make_xml_plain('device', { 'id' => did })
    end
    req_ag << req_devices
    req    << req_ag
    r = execute(req)
  end

  #-------------------------------------------------------------------------
  # Returns all asset group information
  #-------------------------------------------------------------------------
  def asset_groups_listing()
    r = execute(make_xml('AssetGroupListingRequest'))

    if r.success
      res = []
      r.res.elements.each('//AssetGroupSummary') do |group|
        res << {
            :asset_group_id => group.attributes['id'].to_i,
            :name => group.attributes['name'].to_s,
            :description => group.attributes['description'].to_s,
            :risk_score => group.attributes['riskscore'].to_f,
        }
      end
      res
    else
      false
    end
  end

  #-------------------------------------------------------------------------
  # Returns an asset group configuration information for a specific group ID
  #-------------------------------------------------------------------------
  def asset_group_config(group_id)
    r = execute(make_xml('AssetGroupConfigRequest', {'group-id' => group_id}))

    if r.success
      res = []
      r.res.elements.each('//Devices/device') do |device_info|
        res << {
            :device_id => device_info.attributes['id'].to_i,
            :site_id => device_info.attributes['site-id'].to_i,
            :address => device_info.attributes['address'].to_s,
            :riskfactor => device_info.attributes['riskfactor'].to_f,
        }
      end
      res
    else
      false
    end
  end

  #-----------------------------------------------------------------------
  # Starts device specific site scanning.
  #
  # devices - An Array of device IDs
  # hosts - An Array of Hashes [o]=>{:range=>"to,from"} [1]=>{:host=>host}
  #-----------------------------------------------------------------------
  def site_device_scan_start(site_id, devices, hosts)

    if hosts == nil and devices == nil
      raise ArgumentError.new("Both the device and host list is nil")
    end

    xml = make_xml('SiteDevicesScanRequest', {'site-id' => site_id})

    if devices != nil
      inner_xml = REXML::Element.new 'Devices'
      for device_id in devices
        inner_xml.add_element 'device', {'id' => "#{device_id}"}
      end
      xml.add_element inner_xml
    end

    if hosts != nil
      inner_xml = REXML::Element.new 'Hosts'
      hosts.each_index do |x|
        if hosts[x].key? :range
          to = hosts[x][:range].split(',')[0]
          from = hosts[x][:range].split(',')[1]
          inner_xml.add_element 'range', {'to' => "#{to}", 'from' => "#{from}"}
        end
        if hosts[x].key? :host
          host_element = REXML::Element.new 'host'
          host_element.text = "#{hosts[x][:host]}"
          inner_xml.add_element host_element
        end
      end
      xml.add_element inner_xml
    end

    r = execute xml
    if r.success
      r.res.elements.each('//Scan') do |scan_info|
        return {
            :scan_id => scan_info.attributes['scan-id'].to_i,
            :engine_id => scan_info.attributes['engine-id'].to_i
        }
      end
    else
      false
    end
  end

  def site_delete(param)
    r = execute(make_xml('SiteDeleteRequest', { 'site-id' => param }))
    r.success
  end

  def site_listing
    r = execute(make_xml('SiteListingRequest', { }))

    if(r.success)
      res = []
      r.res.elements.each("//SiteSummary") do |site|
        res << {
          :site_id       => site.attributes['id'].to_i,
          :name          => site.attributes['name'].to_s,
          :risk_factor   => site.attributes['risk_factor'].to_f,
          :risk_score    => site.attributes['risk_score'].to_f,
        }
      end
      return res
    else
      return false
    end
  end

  #-----------------------------------------------------------------------
  # TODO: Needs to be expanded to included details
  #-----------------------------------------------------------------------
  def site_scan_history(site_id)
    r = execute(make_xml('SiteScanHistoryRequest', {'site-id' => site_id.to_s}))

    if (r.success)
      res = []
      r.res.elements.each("//ScanSummary") do |site_scan_history|
        res << {
            :site_id => site_scan_history.attributes['site-id'].to_i,
            :scan_id => site_scan_history.attributes['scan-id'].to_i,
            :engine_id => site_scan_history.attributes['engine-id'].to_i,
            :start_time => site_scan_history.attributes['startTime'].to_s,
            :end_time => site_scan_history.attributes['endTime'].to_s
        }
      end
      return res
    else
      false
    end
  end

  def site_device_listing(site_id)
    r = execute(make_xml('SiteDeviceListingRequest', { 'site-id' => site_id.to_s }))

    if(r.success)
      res = []
      r.res.elements.each("//device") do |device|
        res << {
          :device_id     => device.attributes['id'].to_i,
          :address       => device.attributes['address'].to_s,
          :risk_factor   => device.attributes['risk_factor'].to_f,
          :risk_score    => device.attributes['risk_score'].to_f,
        }
      end
      return res
    else
      return false
    end
  end

  def report_template_listing
    r = execute(make_xml('ReportTemplateListingRequest', { }))

    if(r.success)
      res = []
      r.res.elements.each("//ReportTemplateSummary") do |template|
        desc = ''
        template.elements.each("//description") do |ent|
          desc = ent.text
        end

        res << {
          :template_id   => template.attributes['id'].to_s,
          :name          => template.attributes['name'].to_s,
          :description   => desc.to_s
        }
      end
      return res
    else
      return false
    end
  end


  def console_command(cmd_string)
    xml = make_xml('ConsoleCommandRequest', {  })
    cmd = REXML::Element.new('Command')
    cmd.text = cmd_string
    xml << cmd

    r = execute(xml)

    if(r.success)
      res = ""
      r.res.elements.each("//Output") do |out|
        res << out.text.to_s
      end

      return res
    else
      return false
    end
  end

  def system_information
    r = execute(make_xml('SystemInformationRequest', { }))

    if(r.success)
      res = {}
      r.res.elements.each("//Statistic") do |stat|
        res[ stat.attributes['name'].to_s ] = stat.text.to_s
      end

      return res
    else
      return false
    end
  end

end

# === Description
# Object that represents a connection to a Nexpose Security Console.
#
# === Examples
#   # Create a new Nexpose Connection on the default port
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#
#   # Login to NSC and Establish a Session ID
#   nsc.login()
#
#   # Check Session ID
#   if (nsc.session_id)
#       puts "Login Successful"
#   else
#       puts "Login Failure"
#   end
#
#   # //Logout
#   logout_success = nsc.logout()
#   if (! logout_success)
#       puts "Logout Failure" + "<p>" + nsc.error_msg.to_s
#   end
#
class Connection
  include XMLUtils
  include NexposeAPI

  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # Session ID of this connection
  attr_reader :session_id
  # The hostname or IP Address of the NSC
  attr_reader :host
  # The port of the NSC (default is 3780)
  attr_reader :port
  # The username used to login to the NSC
  attr_reader :username
  # The password used to login to the NSC
  attr_reader :password
  # The URL for communication
  attr_reader :url

  # Constructor for Connection
  def initialize(ip, user, pass, port = 3780)
    @host = ip
    @port = port
    @username = user
    @password = pass
    @session_id = nil
    @error = false
    @url = "https://#{@host}:#{@port}/api/1.1/xml"
    @url_base = "https://#{@host}:#{@port}/api/"
  end

  # Establish a new connection and Session ID
  def login

    # This throws an APIError exception if necessary
    r = execute(make_xml('LoginRequest', { 'sync-id' => 0, 'password' => @password, 'user-id' => @username }))
    if(r.success)
      @session_id = r.sid
      return true
    end

    false
  end

  # Logout of the current connection
  def logout
    # Bypass logout unless we have an actual session ID
    return true unless @session_id

    r = execute(make_xml('LogoutRequest', {'sync-id' => 0}))
    if(r.success)
      return true
    end
    raise APIError.new(r, 'Logout failed')
  end

  # Execute an API request
  def execute(xml, version='1.1')
    APIRequest.execute("#{@url_base}#{version}/xml", xml.to_s)
  end

  # Download a specific URL
  def download(url)
    uri = URI.parse(url)
    http = Net::HTTP.new(@host, @port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE            # XXX: security issue
    headers = {'Cookie' => "nexposeCCSessionID=#{@session_id}"}
    resp = http.get(uri.path, headers)

    resp ? resp.body : nil
  end
end

# === Description
# Object that represents a listing of all of the sites available on an NSC.
#
# === Example
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc->login();
#
#   # Get Site Listing
#   sitelisting = SiteListing.new(nsc)
#
#   # Enumerate through all of the SiteSummaries
#   sitelisting.sites.each do |sitesummary|
#       # Do some operation on each site
#   end
#
class SiteListing
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # Array containing SiteSummary objects for each site in the connection
  attr_reader :sites
  # The number of sites
  attr_reader :site_count

  # Constructor
  # SiteListing (connection)
  def initialize(connection)
    @sites = []

    @connection = connection

    r = @connection.execute('<SiteListingRequest session-id="' + @connection.session_id.to_s + '"/>')

    if (r.success)
      parse(r.res)
    else
      raise APIError.new(r, "Failed to get site listing")
    end
  end

  def parse(r)
    r.elements.each('SiteListingResponse/SiteSummary') do |s|
      site_summary = SiteSummary.new(
        s.attributes['id'].to_s,
        s.attributes['name'].to_s,
        s.attributes['description'].to_s,
        s.attributes['riskfactor'].to_s
      )
      @sites.push(site_summary)
    end
    @site_count = @sites.length
  end
end

# === Description
# Object that represents the summary of a Nexpose Site.
#
class SiteSummary
  # The Site ID
  attr_reader :id
  # The Site Name
  attr_reader :site_name
  # A Description of the Site
  attr_reader :description
  # User assigned risk multiplier
  attr_reader :riskfactor

  # Constructor
  # SiteSummary(id, site_name, description, riskfactor = 1)
  def initialize(id, site_name, description, riskfactor = 1)
    @id = id
    @site_name = site_name
    @description = description
    @riskfactor = riskfactor
  end

  def _set_id(id)
    @id = id
  end
end

# === Description
# Object that represents a single IP address or an inclusive range of IP addresses. If to is nil then the from field will be used to specify a single IP Address only.
#
class IPRange
  # Start of Range *Required
  attr_reader :from;
  # End of Range *Optional (If Null then IPRange is a single IP Address)
  attr_reader :to;

  def initialize(from, to = nil)
    @from = from
    @to = to
  end

  include Sanitize
  def to_xml
    if (to and not to.empty?)
      return %Q{<range from="#{from}" to="#{to}"/>}
    else
      return %Q{<range from="#{from}"/>}
    end
  end
end

# === Description
# Object that represents a hostname to be added to a site.
class HostName

  # The hostname
  attr_reader :hostname

  def initialize(hostname)
    @hostname = hostname
  end

  include Sanitize
  def to_xml
    "<host>#{replace_entities(hostname)}</host>"
  end
end

# === Description
# Object that represents the configuration of a Site. This object is automatically created when a new Site object is instantiated.
#
class SiteConfig
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The Site ID
  attr_reader :site_id
  # The Site Name
  attr_reader :site_name
  # A Description of the Site
  attr_reader :description
  # User assigned risk multiplier
  attr_reader :riskfactor
  # Array containing ((IPRange|HostName)*)
  attr_reader :hosts
  # Array containing (AdminCredentials*)
  attr_reader :credentials
  # Array containing ((SmtpAlera|SnmpAlert|SyslogAlert)*)
  attr_reader :alerts
  # ScanConfig object which holds Schedule and ScanTrigger Objects
  attr_reader :scanConfig

  def initialize()
    @xml_tag_stack = Array.new()
    @hosts = Array.new()
    @credentials = Array.new()
    @alerts = Array.new()
    @error = false
  end

  # Adds a new host to the hosts array
  def addHost(host)
    @hosts.push(host)
  end

  # Adds a new alert to the alerts array
  def addAlert(alert)
    @alerts.push(alert)
  end

  # Adds a new set of credentials to the credentials array
  def addCredentials(credential)
    @credentials.push(credential)
  end

  # TODO
  def getSiteConfig(connection,site_id)
    @connection = connection
    @site_id = site_id

    r = APIRequest.execute(@connection.url,'<SiteConfigRequest session-id="' + @connection.session_id + '" site-id="' + @site_id + '"/>')
    parse(r.res)
  end

  def _set_site_id(site_id)
    @site_id = site_id
  end

  def _set_site_name(site_name)
    @site_name = site_name
  end

  def _set_description(description)
    @description = description
  end

  def _set_riskfactor(riskfactor)
    @riskfactor = riskfactor
  end

  def _set_scanConfig(scanConfig)
    @scanConfig = scanConfig
  end

  def _set_connection(connection)
    @connection = connection
  end
=begin
<SiteConfigResponse success='1'>
<Site name='Site1' id='243' description='' riskfactor='1.0'>
<Hosts>
<range from='127.0.0.1'/>
</Hosts>
<Credentials>
</Credentials>
<Alerting>
</Alerting>
<ScanConfig configID='243' name='Full audit' configVersion='3' engineID='2' templateID='full-audit'>
<Schedules>
</Schedules>
<ScanTriggers>
</ScanTriggers>
</ScanConfig>
</Site>

=end

  def parse(response)
    response.elements.each('SiteConfigResponse/Site') do |s|
      @site_id = s.attributes['id']
      @site_name = s.attributes['name']
      @description = s.attributes['description']
      @riskfactor = s.attributes['riskfactor']
      s.elements.each('Hosts/range') do |r|
        @hosts.push(IPRange.new(r.attributes['from'],r.attributes['to']))
      end
      s.elements.each('ScanConfig') do |c|
        @scanConfig = ScanConfig.new(c.attributes['configID'],
                      c.attributes['name'],
                      c.attributes['configVersion'],
                      c.attributes['templateID'])
        s.elements.each('Schedule') do |schedule|
          schedule = new Schedule(schedule.attributes["type"], schedule.attributes["interval"], schedule.attributes["start"], schedule.attributes["enabled"])
          @scanConfig.addSchedule(schedule)
        end
      end

      s.elements.each('Alerting/Alert') do |a|

        a.elements.each('smtpAlert') do |smtp|
          smtp_alert = SmtpAlert.new(a.attributes["name"], smtp.attributes["sender"], smtp.attributes["limitText"], a.attributes["enabled"])

          smtp.elements.each('recipient') do |recipient|
            smtp_alert.addRecipient(recipient.text)
          end
          @alerts.push(smtp_alert)
        end

        a.elements.each('snmpAlert') do |snmp|
          snmp_alert = SnmpAlert.new(a.attributes["name"], snmp.attributes["community"], snmp.attributes["server"], a.attributes["enabled"])
          @alerts.push(snmp_alert)
        end
        a.elements.each('syslogAlert') do |syslog|
          syslog_alert = SyslogAlert.new(a.attributes["name"], syslog.attributes["server"], a.attributes["enabled"])
          @alerts.push(syslog_alert)
        end

        a.elements.each('vulnFilter') do |vulnFilter|

          #vulnfilter = new VulnFilter.new(a.attributes["typemask"], a.attributes["severityThreshold"], $attrs["MAXALERTS"])
          # Pop off the top alert on the stack
          #$alert = @alerts.pop()
          # Add the new recipient string to the Alert Object
          #$alert.setVulnFilter($vulnfilter)
          # Push the alert back on to the alert stack
          #array_push($this->alerts, $alert)
        end

        a.elements.each('scanFilter') do |scanFilter|
          #<scanFilter scanStop='0' scanFailed='0' scanStart='1'/>
          #scanfilter = ScanFilter.new(scanFilter.attributes['scanStop'],scanFilter.attributes['scanFailed'],scanFilter.attributes['scanStart'])
          #alert = @alerts.pop()
          #alert.setScanFilter(scanfilter)
          #@alerts.push(alert)
        end
      end
    end
  end
end

# === Description
# Object that represents the scan history of a site.
#
class SiteScanHistory
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The Site ID
  attr_reader :site_id
  # //Array containing (ScanSummary*)
  attr_reader :scan_summaries

  def initialize(connection, id)
    @site_id = id
    @error = false
    @connection = connection
    @scan_summaries = Array.new()

    r = @connection.execute('<SiteScanHistoryRequest' + ' session-id="' + @connection.session_id + '" site-id="' + @site_id + '"/>')
    status = r.success
  end
end

# === Description
# Object that represents a listing of devices for a site or the entire NSC. Note that only devices which are accessible to the account used to create the connection object will be returned. This object is created and populated automatically with the instantiation of a new Site object.
#
class SiteDeviceListing

  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The Site ID. 0 if all sites are specified.
  attr_reader :site_id
  # //Array of (Device)*
  attr_reader :devices

  def initialize(connection, site_id = 0)

    @site_id = site_id
    @error = false
    @connection = connection
    @devices = Array.new()

    r = nil
    if (@site_id)
      r = @connection.execute('<SiteDeviceListingRequest session-id="' + connection.session_id + '" site-id="' + @site_id + '"/>')
    else
      r = @connection.execute('<SiteDeviceListingRequest session-id="' + connection.session_id + '"/>')
    end

    if(r.success)
      response.elements.each('SiteDeviceListingResponse/SiteDevices/device') do |d|
        @devices.push(Device.new(d.attributes['id'],@site_id,d.attributes["address"],d.attributes["riskfactor"],d.attributes['riskscore']))
      end
    end
  end
end

# === Description
# Object that represents a site, including the site configuration, scan history, and device listing.
#
# === Example
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc.login()
#
#   # Get an Existing Site
#   site_existing = Site.new(nsc,184)
#
#   # Create a New Site, add some hosts, and save it to the NSC
#   site = Site.new(nsc)
#   site.setSiteConfig("New Site", "New Site Created in the API")
#
#   # Add the hosts
#   site.site_config.addHost(HostName.new("localhost"))
#   site.site_config.addHost(IPRange.new("192.168.7.1","192.168.7.255"))
#   site.site_config.addHost(IPRange.new("10.1.20.30"))
#
#   status = site.saveSite()
#
class Site
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The Site ID
  # site_id = -1 means create a new site. The NSC will assign a new site_id on SiteSave.
  attr_reader :site_id
  # A summary overview of this site
  # SiteSummary Object
  attr_reader :site_summary
  # The configuration of this site
  # SiteConfig Object
  attr_reader :site_config
  # The device listing for this site
  # SiteDeviceListing Object
  attr_reader :site_device_listing
  # The scan history of this site
  # SiteScanHistory Object
  attr_reader :site_scan_history

  def initialize(connection, site_id = -1)
    @error = false
    @connection = connection
    @site_id = site_id

    # If site_id > 0 then get SiteConfig
    if (@site_id.to_i > 0)
      # Create new SiteConfig object
      @site_config = SiteConfig.new()
      # Populate SiteConfig Obect with Data from the NSC
      @site_config.getSiteConfig(@connection,@site_id)
      @site_summary = SiteSummary.new(@site_id, @site_config.site_name, @site_config.description, @site_config.riskfactor)
      @site_scan_history = SiteScanHistory.new(@connection,@site_id)
      @site_device_listing = SiteDeviceListing.new(@connection,@site_id)

    else
      # Just in case user enters a number > -1 or = 0
      @site_id = -1

      @site_config = SiteConfig.new()
      setSiteConfig("New Site " + rand(999999999999).to_s,"")
      @site_summary = nil

    end

  end

  # Creates a new site summary
  def setSiteSummary(site_name, description, riskfactor = 1)
    @site_summary = SiteSummary.new(-1,site_name,description,riskfactor)

  end

  # Creates a new site configuration
  def setSiteConfig(site_name, description, riskfactor = 1)
    setSiteSummary(site_name,description,riskfactor)
    @site_config = SiteConfig.new()
    @site_config._set_site_id(-1)
    @site_config._set_site_name(site_name)
    @site_config._set_description(description)
    @site_config._set_riskfactor(riskfactor)
    @site_config._set_scanConfig(ScanConfig.new(-1,"tmp","full-audit"))
    @site_config._set_connection(@connection)

  end

  # Initiates a scan of this site. If successful returns scan_id and engine_id in an associative array. Returns false if scan is unsuccessful.
  def scanSite()
    r = @connection.execute('<SiteScanRequest session-id="' + "#{@connection.session_id}" + '" site-id="' + "#{@site_id}" + '"/>')
    if(r.success)
      res = {}
      r.res.elements.each('//Scan/') do |s|
        res[:scan_id]   = s.attributes['scan-id']
        res[:engine_id] = s.attributes['engine-id']
      end
      return res
    else
      return false
    end
  end

  # Saves this site in the NSC
  def saveSite()
    r = @connection.execute('<SiteSaveRequest session-id="' + @connection.session_id + '">' + getSiteXML() + ' </SiteSaveRequest>')
    if (r.success)
      @site_id =  r.attributes['site-id']
      @site_config._set_site_id(@site_id)
      @site_config.scanConfig._set_configID(@site_id)
      @site_config.scanConfig._set_name(@site_id)
      return true
    else
      return false
    end
  end

  def deleteSite()
    r = @connection.execute('<SiteDeleteRequest session-id="' + @connection.session_id.to_s + '" site-id="' + @site_id + '"/>')
    r.success
  end


  def printSite()
    puts "Site ID: " + @site_summary.id
    puts "Site Name: " + @site_summary.site_name
    puts "Site Description: " + @site_summary.description
    puts "Site Risk Factor: " + @site_summary.riskfactor
  end

  def getSiteXML()

    xml = '<Site id="' + "#{@site_config.site_id}" + '" name="' + "#{@site_config.site_name}" + '" description="' + "#{@site_config.description}" + '" riskfactor="' + "#{@site_config.riskfactor}" + '">'

    xml << ' <Hosts>'
    @site_config.hosts.each do |h|
      xml << h.to_xml if h.respond_to? :to_xml
    end
    xml << '</Hosts>'

    xml << '<Credentials>'
    @site_config.credentials.each do |c|
      xml << c.to_xml if c.respond_to? :to_xml
    end
    xml << ' </Credentials>'

    xml << ' <Alerting>'
    @site_config.alerts.each do |a|
      xml << a.to_xml if a.respond_to? :to_xml
    end
    xml << ' </Alerting>'

    xml << ' <ScanConfig configID="' + "#{@site_config.scanConfig.configID}" + '" name="' + "#{@site_config.scanConfig.name}" + '" templateID="' + "#{@site_config.scanConfig.templateID}" + '" configVersion="' + "#{@site_config.scanConfig.configVersion}" + '">'

    xml << ' <Schedules>'
    @site_config.scanConfig.schedules.each do |s|
      xml << ' <Schedule enabled="' + s.enabled + '" type="' + s.type + '" interval="' + s.interval + '" start="' + s.start + '"/>'
    end
    xml << ' </Schedules>'

    xml << ' <ScanTriggers>'
    @site_config.scanConfig.scanTriggers.each do |s|

      if (s.class.to_s == "Nexpose::AutoUpdate")
        xml << ' <autoUpdate enabled="' + s.enabled + '" incremental="' + s.incremental + '"/>'
      end
    end

    xml << ' </ScanTriggers>'

    xml << ' </ScanConfig>'

    xml << ' </Site>'

    return xml
  end
end

# === Description
# Object that represents administrative credentials to be used during a scan. When retrived from an existing site configuration the credentials will be returned as a security blob and can only be passed back as is during a Site Save operation. This object can only be used to create a new set of credentials.
#
class AdminCredentials
  # Security blob for an existing set of credentials
  attr_reader :securityblob
  # Designates if this object contains user defined credentials or a security blob
  attr_reader :isblob
  # The service for these credentials. Can be All.
  attr_reader :service
  # The host for these credentials. Can be Any.
  attr_reader :host
  # The port on which to use these credentials.
  attr_reader :port
  # The user id or username
  attr_reader :userid
  # The password
  attr_reader :password
  # The realm for these credentials
  attr_reader :realm


  def initialize(isblob = false)
    @isblob = isblob
  end

  # Sets the credentials information for this object.
  def setCredentials(service, host, port, userid, password, realm)
    @isblob = false
    @securityblob = nil
    @service = service
    @host = host
    @port = port
    @userid = userid
    @password = password
    @realm = realm
  end

  # TODO: add description
  def setService(service)
    @service = service
  end

  def setHost(host)
    @host = host
  end

  # TODO: add description
  def setBlob(securityblob)
    @isblob = true
    @securityblob = securityblob
  end

  include Sanitize
  def to_xml
    xml = ''
    xml << '<adminCredentials'
    xml << %Q{ service="#{replace_entities(service)}"} if (service)
    xml << %Q{ userid="#{replace_entities(userid)}"} if (userid)
    xml << %Q{ password="#{replace_entities(password)}"} if (password)
    xml << %Q{ realm="#{replace_entities(realm)}"} if (realm)
    xml << %Q{ host="#{replace_entities(host)}"} if (host)
    xml << %Q{ port="#{replace_entities(port)}"} if (port)
    xml << '>'
    xml << replace_entities(securityblob) if (isblob)
    xml << '</adminCredentials>'

    xml
  end
end


# === Description
# Object that represents an SMTP (Email) Alert.
#
class SmtpAlert
  # A unique name for this alert
  attr_reader :name
  # If this alert is enabled or not
  attr_reader :enabled
  # The email address of the sender
  attr_reader :sender
  # Limit the text for mobile devices
  attr_reader :limitText
  # Array containing Strings of email addresses
  # Array of strings with the email addresses of the intended recipients
  attr_reader :recipients
  # The vulnerability filter to trigger the alert
  attr_reader :vulnFilter
  # The alert type
  attr_reader :type

  def initialize(name, sender, limitText, enabled = 1)
    @type = :smtp
    @name = name
    @sender = sender
    @enabled = enabled
    @limitText = limitText
    @recipients = Array.new()
    # Sets default vuln filter - All Events
    setVulnFilter(VulnFilter.new("50790400",1))
  end

  # Adds a new Recipient to the recipients array
  def addRecipient(recipient)
    @recipients.push(recipient)
  end

  # Sets the Vulnerability Filter for this alert.
  def setVulnFilter(vulnFilter)
    @vulnFilter = vulnFilter
  end

  include Sanitize
  def to_xml
    xml = "<smtpAlert"
    xml << %Q{ name="#{replace_entities(name)}"}
    xml << %Q{ enabled="#{replace_entities(enabled)}"}
    xml << %Q{ sender="#{replace_entities(sender)}"}
    xml << %Q{ limitText="#{replace_entities(limitText)}">}
    recipients.each do |recpt|
      xml << "<recipient>#{replace_entities(recpt)}</recipient>"
    end
    xml << vulnFilter.to_xml
    xml << "</smtpAlert>"
    xml
  end
end

# === Description
# Object that represents an SNMP Alert.
#
class SnmpAlert

  # A unique name for this alert
  attr_reader :name
  # If this alert is enabled or not
  attr_reader :enabled
  # The community string
  attr_reader :community
  # The SNMP server to sent this alert
  attr_reader :server
  # The vulnerability filter to trigger the alert
  attr_reader :vulnFilter
  # The alert type
  attr_reader :type

  def initialize(name, community, server, enabled = 1)
    @type = :snmp
    @name = name
    @community = community
    @server = server
    @enabled = enabled
    # Sets default vuln filter - All Events
    setVulnFilter(VulnFilter.new("50790400",1))
  end

  # Sets the Vulnerability Filter for this alert.
  def setVulnFilter(vulnFilter)
    @vulnFilter = vulnFilter
  end

  include Sanitize
  def to_xml
    xml = "<snmpAlert"
    xml << %Q{ name="#{replace_entities(name)}"}
    xml << %Q{ enabled="#{replace_entities(enabled)}"}
    xml << %Q{ community="#{replace_entities(community)}"}
    xml << %Q{ server="#{replace_entities(server)}">}
    xml << vulnFilter.to_xml
    xml << "</snmpAlert>"
    xml
  end

end

# === Description
# Object that represents a Syslog Alert.
#
class SyslogAlert

  # A unique name for this alert
  attr_reader :name
  # If this alert is enabled or not
  attr_reader :enabled
  # The Syslog server to sent this alert
  attr_reader :server
  # The vulnerability filter to trigger the alert
  attr_reader :vulnFilter
  # The alert type
  attr_reader :type

  def initialize(name, server, enabled = 1)
    @type = :syslog
    @name = name
    @server = server
    @enabled = enabled
    # Sets default vuln filter - All Events
    setVulnFilter(VulnFilter.new("50790400",1))

  end

  # Sets the Vulnerability Filter for this alert.
  def setVulnFilter(vulnFilter)
    @vulnFilter = vulnFilter
  end

  include Sanitize
  def to_xml
    xml = "<syslogAlert"
    xml << %Q{ name="#{replace_entities(name)}"}
    xml << %Q{ enabled="#{replace_entities(enabled)}"}
    xml << %Q{ server="#{replace_entities(server)}">}
    xml << vulnFilter.to_xml
    xml << "</syslogAlert>"
    xml
  end

end

# TODO: review
# <scanFilter scanStop='0' scanFailed='0' scanStart='1'/>
# === Description
#
class ScanFilter

  attr_reader :scanStop
  attr_reader :scanFailed
  attr_reader :scanStart

  def initialize(scanstop, scanFailed, scanStart)

    @scanStop = scanStop
    @scanFailed = scanFailed
    @scanStart = scanStart

  end

end

# TODO: review
# === Description
#
class VulnFilter

  attr_reader :typeMask
  attr_reader :maxAlerts
  attr_reader :severityThreshold

  def initialize(typeMask, severityThreshold, maxAlerts = -1)
    @typeMask = typeMask
    @maxAlerts = maxAlerts
    @severityThreshold = severityThreshold
  end

  include Sanitize
  def to_xml
    xml = "<vulnFilter "
    xml << %Q{ typeMask="#{replace_entities(typeMask)}"}
    xml << %Q{ maxAlerts="#{replace_entities(maxAlerts)}"}
    xml << %Q{ severityThreshold="#{replace_entities(severityThreshold)}"}
    xml << "/>"

    xml
  end

end

# TODO add engineID
# === Description
# Object that represents the scanning configuration for a Site.
#
class ScanConfig
  # A unique ID for this scan configuration
  attr_reader :configID
  # The name of the scan template
  attr_reader :name
  # The ID of the scan template used full-audit, exhaustive-audit, web-audit, dos-audit, internet-audit, network-audit
  attr_reader :templateID
  # The configuration version (default is 2)
  attr_reader :configVersion
  # Array of (Schedule)*
  attr_reader :schedules
  # Array of (ScanTrigger)*
  attr_reader :scanTriggers

  def initialize(configID, name, templateID, configVersion = 2)

    @configID = configID
    @name = name
    @templateID = templateID
    @configVersion = configVersion
    @schedules = Array.new()
    @scanTriggers = Array.new()

  end

  # Adds a new Schedule for this ScanConfig
  def addSchedule(schedule)
    @schedules.push(schedule)
  end

  # Adds a new ScanTrigger to the scanTriggers array
  def addScanTrigger(scanTrigger)
    @scanTriggers.push(scanTrigger)
  end

  def _set_configID(configID)
    @configID = configID
  end

  def _set_name(name)
    @name = name
  end

end

# === Description
# Object that holds a scan schedule
#
class Schedule
  # Type of Schedule (daily|hourly|monthly|weekly)
  attr_reader :type
  # The schedule interval
  attr_reader :interval
  # The date and time to start the first scan
  attr_reader :start
  # Enable or disable this schedule
  attr_reader :enabled
  # The date and time to disable to schedule. If null then the schedule will run forever.
  attr_reader :notValidAfter
  # Scan on the same date each time
  attr_reader :byDate

  def initialize(type, interval, start, enabled = 1)

    @type = type
    @interval = interval
    @start = start
    @enabled = enabled

  end



end

# === Description
# Object that holds an event that triggers the start of a scan.
#
class ScanTrigger
  # Type of Trigger (AutoUpdate)
  attr_reader :type
  # Enable or disable this scan trigger
  attr_reader :enabled
  # Sets the trigger to start an incremental scan or a full scan
  attr_reader :incremental

  def initialize(type, incremental, enabled = 1)

    @type = type
    @incremental = incremental
    @enabled = enabled

  end

end

# === Description
# Object that represents a single device in an NSC.
#
class Device

  # A unique device ID (assigned by the NSC)
  attr_reader :id
  # The site ID of this devices site
  attr_reader :site_id
  # IP Address or Hostname of this device
  attr_reader :address
  # User assigned risk multiplier
  attr_reader :riskfactor
  # Nexpose risk score
  attr_reader :riskscore

  def initialize(id, site_id, address, riskfactor=1, riskscore=0)
    @id = id
    @site_id = site_id
    @address = address
    @riskfactor = riskfactor
    @riskscore = riskscore

  end

end


# === Description
# Object that represents a summary of a scan.
#
class ScanSummary
  # The Scan ID of the Scan
  attr_reader :scan_id
  # The Engine ID used to perform the scan
  attr_reader :engine_id
  # TODO: add description
  attr_reader :name
  # The scan start time
  attr_reader :startTime
  # The scan finish time
  attr_reader :endTime
  # The scan status (running|finished|stopped|error| dispatched|paused|aborted|uknown)
  attr_reader :status
  # The number of pending tasks
  attr_reader :tasks_pending
  # The number of active tasks
  attr_reader :tasks_active
  # The number of completed tasks
  attr_reader :tasks_completed
  # The number of "live" nodes
  attr_reader :nodes_live
  # The number of "dead" nodes
  attr_reader :nodes_dead
  # The number of filtered nodes
  attr_reader :nodes_filtered
  # The number of unresolved nodes
  attr_reader :nodes_unresolved
  # The number of "other" nodes
  attr_reader :nodes_other
  # Confirmed vulnerabilities found (indexed by severity)
  # Associative array, indexed by severity
  attr_reader :vuln_exploit
  # Unconfirmed vulnerabilities found (indexed by severity)
  # Associative array, indexed by severity
  attr_reader :vuln_version
  # Not vulnerable checks run (confirmed)
  attr_reader :not_vuln_exploit
  # Not vulnerable checks run (unconfirmed)
  attr_reader :not_vuln_version
  # Vulnerability check errors
  attr_reader :vuln_error
  # Vulnerability checks disabled
  attr_reader :vuln_disabled
  # Vulnerability checks other
  attr_reader :vuln_other

  # Constructor
  # ScanSummary(can_id, $engine_id, $name, tartTime, $endTime, tatus)
  def initialize(scan_id, engine_id, name, startTime, endTime, status)

    @scan_id = scan_id
    @engine_id = engine_id
    @name = name
    @startTime = startTime
    @endTime = endTime
    @status = status

  end

end

# TODO
# === Description
# Object that represents the overview statistics for a particular scan.
#
# === Examples
#
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc.login()
#
#   # Get a Site (Site ID = 12) from the NSC
#   site = new Site(nsc,12)
#
#   # Start a Scan of this site and pause for 1 minute
#   scan1 = site.scanSite()
#   sleep(60)
#
#   # Get the Scan Statistics for this scan
#   scanStatistics = new ScanStatistics(nsc,scan1["scan_id"])
#
#   # Print out number of confirmed vulnerabilities with a 10 severity
#   puts scanStatistics.scansummary.vuln_exploit[10]
#
#   # Print out the number of pending tasks left in the scan
#   puts scanStatistics.scan_summary.tasks_pending
#
class ScanStatistics
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :reseponse_xml
  # The Scan ID
  attr_reader :scan_id
  # The ScanSummary of the scan
  attr_reader :scan_summary
  # The NSC Connection associated with this object
  attr_reader :connection

  # Vulnerability checks other
  attr_reader :vuln_other
  def initialize(connection, scan_id)
    @error = false
    @connection = connection
    @scan_id = scan_id
  end
end

# ==== Description
# Object that represents a listing of all of the scan engines available on to an NSC.
#
class EngineListing
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # Array containing (EngineSummary*)
  attr_reader :engines
  # The number of scan engines
  attr_reader :engine_count

  # Constructor
  # EngineListing (connection)
  def initialize(connection)
    @connection = connection
  end
end

# ==== Description
# Object that represents the summary of a scan engine.
#
# ==== Examples
#
#   # Create a new Nexpose Connection on the default port and Login
#   nsc = Connection.new("10.1.40.10","nxadmin","password")
#   nsc.login()
#
#   # Get the engine listing for the connection
#   enginelisting = EngineListing.new(nsc)
#
#   # Print out the status of the first scan engine
#   puts enginelisting.engines[0].status
#
class EngineSummary
  # A unique ID that identifies this scan engine
  attr_reader :id
  # The name of this scan engine
  attr_reader :name
  # The hostname or IP address of the engine
  attr_reader :address
  # The port there the engine is listening
  attr_reader :port
  # The engine status (active|pending-auth| incompatible|not-responding|unknown)
  attr_reader :status

  # Constructor
  # EngineSummary(id, name, address, port, status)
  def initialize(id, name, address, port, status)
    @id = id
    @name = name
    @address = address
    @port = port
    @status = status
  end

end


# TODO
class EngineActivity
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The Engine ID
  attr_reader :engine_id
  # Array containing (ScanSummary*)
  attr_reader :scan_summaries


end

# === Description
# Object that represents a listing of all of the vulnerabilities in the vulnerability database
#
class VulnerabilityListing

  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # Array containing (VulnerabilitySummary*)
  attr_reader :vulnerability_summaries
  # The number of vulnerability definitions
  attr_reader :vulnerability_count

  # Constructor
  # VulnerabilityListing(connection)
  def initialize(connection)
    @error = false
    @vulnerability_summaries = []
    @connection = connection

    r = @connection.execute('<VulnerabilityListingRequest session-id="' + @connection.session_id + '"/>')

    if (r.success)
      r.res.elements.each('VulnerabilityListingResponse/VulnerabilitySummary') do |v|
        @vulnerability_summaries.push(VulnerabilitySummary.new(v.attributes['id'],v.attributes["title"],v.attributes["severity"]))
      end
    else
      @error = true
      @error_msg = 'VulnerabilitySummaryRequest Parse Error'
    end
    @vulnerability_count = @vulnerability_summaries.length
  end
end

# === Description
# Object that represents the summary of an entry in the vulnerability database
#
class VulnerabilitySummary

  # The unique ID string for this vulnerability
  attr_reader :id
  # The title of this vulnerability
  attr_reader :title
  # The severity of this vulnerability (1 – 10)
  attr_reader :severity

  # Constructor
  # VulnerabilitySummary(id, title, severity)
  def initialize(id, title, severity)
    @id = id
    @title = title
    @severity = severity

  end

end

# === Description
#
class Reference

  attr_reader :source
  attr_reader :reference

  def initialize(source, reference)
    @source = source
    @reference = reference
  end
end

# === Description
# Object that represents the details for an entry in the vulnerability database
#
class VulnerabilityDetail
  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The unique ID string for this vulnerability
  attr_reader :id
  # The title of this vulnerability
  attr_reader :title
  # The severity of this vulnerability (1 – 10)
  attr_reader :severity
  # The pciSeverity of this vulnerability
  attr_reader :pciSeverity
  # The CVSS score of this vulnerability
  attr_reader :cvssScore
  # The CVSS vector of this vulnerability
  attr_reader :cvssVector
  # The date this vulnerability was published
  attr_reader :published
  # The date this vulnerability was added to Nexpose
  attr_reader :added
  # The last date this vulnerability was modified
  attr_reader :modified
  # The HTML Description of this vulnerability
  attr_reader :description
  # External References for this vulnerability
  # Array containing (Reference)
  attr_reader :references
  # The HTML Solution for this vulnerability
  attr_reader :solution

  # Constructor
  # VulnerabilityListing(connection,id)
  def initialize(connection, id)

    @error = false
    @connection = connection
    @id = id
    @references = []

    r = @connection.execute('<VulnerabilityDetailsRequest session-id="' + @connection.session_id + '" vuln-id="' + @id + '"/>')

    if (r.success)
      r.res.elements.each('VulnerabilityDetailsResponse/Vulnerability') do |v|
        @id = v.attributes['id']
        @title = v.attributes["title"]
        @severity = v.attributes["severity"]
        @pciSeverity = v.attributes['pciSeverity']
        @cvssScore = v.attributes['cvssScore']
        @cvssVector = v.attributes['cvssVector']
        @published = v.attributes['published']
        @added = v.attributes['added']
        @modified = v.attributes['modified']

        v.elements.each('description') do |d|
          @description = d.to_s.gsub(/\<\/?description\>/i, '')
        end

        v.elements.each('solution') do |s|
          @solution = s.to_s.gsub(/\<\/?solution\>/i, '')
        end

        v.elements.each('references/reference') do |r|
          @references.push(Reference.new(r.attributes['source'],r.text))
        end
      end
    else
      @error = true
      @error_msg = 'VulnerabilitySummaryRequest Parse Error'
    end

  end
end

# === Description
# Object that represents the summary of a Report Configuration.
#
class ReportConfigSummary
  # The Report Configuration ID
  attr_reader :id
  # A unique name for the Report
  attr_reader :name
  # The report format
  attr_reader :format
  # The date of the last report generation
  attr_reader :last_generated_on
  # Relative URI of the last generated report
  attr_reader :last_generated_uri

  # Constructor
  # ReportConfigSummary(id, name, format, last_generated_on, last_generated_uri)
  def initialize(id, name, format, last_generated_on, last_generated_uri)

    @id = id
    @name = name
    @format = format
    @last_generated_on = last_generated_on
    @last_generated_uri = last_generated_uri

  end

end

# === Description
# Object that represents the schedule on which to automatically generate new reports.
class ReportHistory

  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The report definition (report config) ID
  # Report definition ID
  attr_reader :config_id
  # Array (ReportSummary*)
  attr_reader :report_summaries


  def initialize(connection, config_id)

    @error = false
    @connection = connection
    @config_id = config_id
    @report_summaries = []

    reportHistory_request = APIRequest.new('<ReportHistoryRequest session-id="' + "#{connection.session_id}" + '" reportcfg-id="' + "#{@config_id}" + '"/>',@connection.geturl())
    reportHistory_request.execute()
    @response_xml = reportHistory_request.response_xml
    @request_xml = reportHistory_request.request_xml

  end

  def xml_parse(response)
    response = REXML::Document.new(response.to_s)
    status =  response.root.attributes['success']
    if (status == '1')
      response.elements.each('ReportHistoryResponse/ReportSummary') do |r|
        @report_summaries.push(ReportSummary.new(r.attributes["id"], r.attributes["cfg-id"], r.attributes["status"], r.attributes["generated-on"],r.attributes['report-uri']))
      end
    else
      @error = true
      @error_msg = 'Error ReportHistoryReponse'
    end
  end

end

# === Description
# Object that represents the summary of a single report.
class ReportSummary

  # The Report ID
  attr_reader :id
  # The Report Configuration ID
  attr_reader :cfg_id
  # The status of this report
  # available | generating | failed
  attr_reader :status
  # The date on which this report was generated
  attr_reader :generated_on
  # The relative URI of the report
  attr_reader :report_uri

  def initialize(id, cfg_id, status, generated_on, report_uri)

    @id = id
    @cfg_id = cfg_id
    @status = status
    @generated_on = generated_on
    @report_uri = report_uri

  end

end

# === Description
#
  class ReportAdHoc
    include XMLUtils

    attr_reader :error
    attr_reader :error_msg
    attr_reader :connection
    # Report Template ID strong e.g. full-audit
    attr_reader :template_id
    # pdf|html|xml|text|csv|raw-xml-v2
    attr_reader :format
    # Array of (ReportFilter)*
    attr_reader :filters
    attr_reader :request_xml
    attr_reader :response_xml
    attr_reader :report_decoded


    def initialize(connection, template_id = 'full-audit', format = 'raw-xml-v2')

      @error = false
      @connection = connection
      @filters = Array.new()
      @template_id = template_id
      @format = format

    end

    def addFilter(filter_type, id)

      # filter_type can be site|group|device|scan
      # id is the ID number. For scan, you can use 'last' for the most recently run scan
      filter = ReportFilter.new(filter_type, id)
      filters.push(filter)

    end

    def generate()
      request_xml = '<ReportAdhocGenerateRequest session-id="' + @connection.session_id + '">'
      request_xml += '<AdhocReportConfig template-id="' + @template_id + '" format="' + @format + '">'
      request_xml += '<Filters>'
      @filters.each do |f|
        request_xml += '<filter type="' + f.type + '" id="'+ f.id.to_s + '"/>'
      end
      request_xml += '</Filters>'
      request_xml += '</AdhocReportConfig>'
      request_xml += '</ReportAdhocGenerateRequest>'

      ad_hoc_request = APIRequest.new(request_xml, @connection.url)
      ad_hoc_request.execute()

      content_type_response = ad_hoc_request.raw_response.header['Content-Type']
      if content_type_response =~ /multipart\/mixed;\s*boundary=([^\s]+)/
        # Nexpose sends an incorrect boundary format which breaks parsing
        # Eg: boundary=XXX; charset=XXX
        # Fix by removing everything from the last semi-colon onward
        last_semi_colon_index = content_type_response.index(/;/, content_type_response.index(/boundary/))
        content_type_response = content_type_response[0, last_semi_colon_index]

        data = "Content-Type: " + content_type_response + "\r\n\r\n" + ad_hoc_request.raw_response_data
        doc = Rex::MIME::Message.new data
        doc.parts.each do |part|
          if /.*base64.*/ =~ part.header.to_s
            return parse_xml(part.content.unpack("m*")[0])
          end
        end
      end
    end

  end

# === Description
# Object that represents the configuration of a report definition.
#
class ReportConfig

  # true if an error condition exists; false otherwise
  attr_reader :error
  # Error message string
  attr_reader :error_msg
  # The last XML request sent by this object
  attr_reader :request_xml
  # The last XML response received by this object
  attr_reader :response_xml
  # The NSC Connection associated with this object
  attr_reader :connection
  # The ID for this report definition
  attr_reader :config_id
  # A unique name for this report definition
  attr_reader :name
  # The template ID used for this report definition
  attr_reader :template_id
  # html, db, txt, xml, raw-xml-v2, csv, pdf
  attr_reader :format
  # XXX new
  attr_reader :timezone
  # XXX new
  attr_reader :owner
  # Array of (ReportFilter)* - The Sites, Asset Groups, or Devices to run the report against
  attr_reader :filters
  # Automatically generate a new report at the conclusion of a scan
  # 1 or 0
  attr_reader :generate_after_scan
  # Schedule to generate reports
  # ReportSchedule Object
  attr_reader :schedule
  # Store the reports on the server
  # 1 or 0
  attr_reader :storeOnServer
  # Location to store the report on the server
  attr_reader :store_location
  # Form to send the report via email
  # "file", "zip", "url", or NULL (don’t send email)
  attr_reader :email_As
  # Send the Email to all Authorized Users
  # boolean - Send the Email to all Authorized Users
  attr_reader :email_to_all
  # Array containing the email addresses of the recipients
  attr_reader :email_recipients
  # IP Address or Hostname of SMTP Relay Server
  attr_reader :smtp_relay_server
  # Sets the FROM field of the Email
  attr_reader :sender
  # TODO
  attr_reader :db_export
  # TODO
  attr_reader :csv_export
  # TODO
  attr_reader :xml_export


  def initialize(connection, config_id = -1)

    @error = false
    @connection = connection
    @config_id = config_id
    @xml_tag_stack = Array.new()
    @filters = Array.new()
    @email_recipients = Array.new()
    @name = "New Report " + rand(999999999).to_s

    r = @connection.execute('<ReportConfigRequest session-id="' + @connection.session_id.to_s + '" reportcfg-id="' + @config_id.to_s + '"/>')
    if (r.success)
      r.res.elements.each('ReportConfigResponse/ReportConfig') do |r|
        @name = r.attributes['name']
        @format = r.attributes['format']
        @timezone = r.attributes['timezone']
        @id = r.attributes['id']
        @template_id = r.attributes['template-id']
        @owner = r.attributes['owner']
      end
    else
      @error = true
      @error_msg = 'Error ReportHistoryReponse'
    end
  end

  # === Description
  # Generate a new report on this report definition. Returns the new report ID.
  def generateReport(debug = false)
    return generateReport(@connection, @config_id, debug)
  end

  # === Description
  # Save the report definition to the NSC.
  # Returns the config-id.
  def saveReport()
    r = @connection.execute('<ReportSaveRequest session-id="' + @connection.session_id.to_s + '">' + getXML().to_s + ' </ReportSaveRequest>')
    if(r.success)
      @config_id = r.attributes['reportcfg-id']
      return true
    end
    return false
  end

  # === Description
  # Adds a new filter to the report config
  def addFilter(filter_type, id)
    filter = ReportFilter.new(filter_type,id)
    @filters.push(filter)
  end

  # === Description
  # Adds a new email recipient
  def addEmailRecipient(recipient)
    @email_recipients.push(recipient)
  end

  # === Description
  # Sets the schedule for this report config
  def setSchedule(schedule)
    @schedule = schedule
  end

  def getXML()

    xml = '<ReportConfig id="' + @config_id.to_s + '" name="' + @name.to_s + '" template-id="' + @template_id.to_s + '" format="' + @format.to_s + '">'

    xml += ' <Filters>'

    @filters.each do |f|
      xml += ' <' + f.type.to_s + ' id="' + f.id.to_s + '"/>'
    end

    xml += ' </Filters>'

    xml += ' <Generate after-scan="' + @generate_after_scan.to_s + '">'

    if (@schedule)
      xml += ' <Schedule type="' + @schedule.type.to_s + '" interval="' + @schedule.interval.to_s + '" start="' + @schedule.start.to_s + '"/>'
    end

    xml += ' </Generate>'

    xml += ' <Delivery>'

    xml += ' <Storage storeOnServer="' + @storeOnServer.to_s + '">'

    if (@store_location and @store_location.length > 0)
      xml += ' <location>' + @store_location.to_s + '</location>'
    end

    xml += ' </Storage>'


    xml += ' </Delivery>'

    xml += ' </ReportConfig>'

    return xml
  end

  def set_name(name)
    @name = name
  end

  def set_template_id(template_id)
    @template_id = template_id
  end

  def set_format(format)
    @format = format
  end

  def set_email_As(email_As)
    @email_As = email_As
  end

  def set_storeOnServer(storeOnServer)
    @storeOnServer = storeOnServer
  end

  def set_smtp_relay_server(smtp_relay_server)
    @smtp_relay_server = smtp_relay_server
  end

  def set_sender(sender)
    @sender = sender
  end

  def set_generate_after_scan(generate_after_scan)
    @generate_after_scan = generate_after_scan
  end
end

# === Description
# Object that represents a report filter which determines which sites, asset
# groups, and/or devices that a report is run against.  gtypes are
# "SiteFilter", "AssetGroupFilter", "DeviceFilter", or "ScanFilter".  gid is
# the site-id, assetgroup-id, or devce-id.  ScanFilter, if used, specifies
# a specifies a specific scan to use as the data source for the report. The gid
# can be a specific scan-id or "first" for the first run scan, or “last” for
# the last run scan.
#
class ReportFilter

  attr_reader :type
  attr_reader :id

  def initialize(type, id)

    @type = type
    @id = id

  end

end

# === Description
# Object that represents the schedule on which to automatically generate new reports.
#
class ReportSchedule

  # The type of schedule
  # (daily, hourly, monthly, weekly)
  attr_reader :type
  # The frequency with which to run the scan
  attr_reader :interval
  # The earliest date to generate the report
  attr_reader :start

  def initialize(type, interval, start)

    @type = type
    @interval = interval
    @start = start

  end


end

class ReportTemplateListing

  attr_reader :error_msg
  attr_reader :error
  attr_reader :request_xml
  attr_reader :response_xml
  attr_reader :connection
  attr_reader :xml_tag_stack
  attr_reader :report_template_summaries#;  //Array (ReportTemplateSummary*)


  def ReportTemplateListing(connection)

    @error = nil
    @connection = connection
    @report_template_summaries = Array.new()

    r = @connection.execute('<ReportTemplateListingRequest session-id="' + connection.session_id.to_s + '"/>')
    if (r.success)
      r.res.elements.each('ReportTemplateListingResponse/ReportTemplateSummary') do |r|
        @report_template_summaries.push(ReportTemplateSumary.new(r.attributes['id'],r.attributes['name']))
      end
    else
      @error = true
      @error_msg = 'ReportTemplateListingRequest Parse Error'
    end

  end

end


class ReportTemplateSummary

  attr_reader :id
  attr_reader :name
  attr_reader :description

  def ReportTemplateSummary(id, name, description)

    @id = id
    @name = name
    @description = description

  end

end


class ReportSection

  attr_reader :name
  attr_reader :properties

  def ReportSection(name)

    @properties = Array.new()
    @name = name
  end


  def addProperty(name, value)

    @properties[name.to_s] = value
  end

end


# TODO add
def self.site_device_scan(connection, site_id, device_array, host_array, debug = false)

  request_xml = '<SiteDevicesScanRequest session-id="' + connection.session_id.to_s + '" site-id="' + site_id.to_s + '">'
  request_xml += '<Devices>'
  device_array.each do |d|
    request_xml += '<device id="' + d.to_s + '"/>'
  end
  request_xml += '</Devices>'
  request_xml += '<Hosts>'
  # The host array can only by single IP addresses for now. TODO: Expand to full API Spec.
  host_array.each do |h|
    request_xml += '<range from="' + h.to_s + '"/>'
  end
  request_xml += '</Hosts>'
  request_xml += '</SiteDevicesScanRequest>'

  r = connection.execute(request_xml)
  r.success ? { :engine_id => r.attributes['engine_id'], :scan_id => r.attributes['scan-id'] } : nil
end

# === Description
# TODO
def self.getAttribute(attribute, xml)
  value = ''
  #@value = substr(substr(strstr(strstr(@xml,@attribute),'"'),1),0,strpos(substr(strstr(strstr(@xml,@attribute),'"'),1),'"'))
  return value
end

# === Description
# Returns an ISO 8601 formatted date/time stamp. All dates in Nexpose must use this format.
def self.get_iso_8601_date(int_date)
#@date_mod = date('Ymd\THis000', @int_date)
  date_mod = ''
return date_mod
end

# ==== Description
# Echos the last XML API request and response for the specified object.  (Useful for debugging)
def self.printXML(object)
  puts "request" + object.request_xml.to_s
  puts "response is " + object.response_xml.to_s
end

end
