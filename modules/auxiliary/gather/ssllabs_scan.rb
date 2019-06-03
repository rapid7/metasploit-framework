##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'active_support/inflector'
require 'json'
require 'active_support/core_ext/hash'

class MetasploitModule < Msf::Auxiliary
  class InvocationError < StandardError; end
  class RequestRateTooHigh < StandardError; end
  class InternalError < StandardError; end
  class ServiceNotAvailable < StandardError; end
  class ServiceOverloaded < StandardError; end

  class Api
    attr_reader :max_assessments, :current_assessments

    def initialize
      @max_assessments = 0
      @current_assessments = 0
    end

    def request(name, params = {})
      api_host = "api.ssllabs.com"
      api_port = "443"
      api_path = "/api/v2/"
      user_agent = "Msf_ssllabs_scan"

      name = name.to_s.camelize(:lower)
      uri = api_path + name
      cli = Rex::Proto::Http::Client.new(api_host, api_port, {}, true, 'TLS')
      cli.connect
      req = cli.request_cgi({
          'uri' => uri,
          'agent' => user_agent,
          'method' => 'GET',
          'vars_get' => params
      })
      res = cli.send_recv(req)
      cli.close

      if res && res.code.to_i == 200
        @max_assessments = res.headers['X-Max-Assessments']
        @current_assessments = res.headers['X-Current-Assessments']
        r = JSON.load(res.body)
        fail InvocationError, "API returned: #{r['errors']}" if r.key?('errors')
        return r
      end

      case res.code.to_i
      when 400
        fail InvocationError
      when 429
        fail RequestRateTooHigh
      when 500
        fail InternalError
      when 503
        fail ServiceNotAvailable
      when 529
        fail ServiceOverloaded
      else
        fail StandardError, "HTTP error code #{r.code}", caller
      end
    end

    def report_unused_attrs(type, unused_attrs)
      unused_attrs.each do | attr |
        # $stderr.puts "#{type} request returned unknown parameter #{attr}"
      end
    end

    def info
      obj, unused_attrs = Info.load request(:info)
      report_unused_attrs('info', unused_attrs)
      obj
    end

    def analyse(params = {})
      obj, unused_attrs = Host.load request(:analyze, params)
      report_unused_attrs('analyze', unused_attrs)
      obj
    end

    def get_endpoint_data(params = {})
      obj, unused_attrs = Endpoint.load request(:get_endpoint_data, params)
      report_unused_attrs('get_endpoint_data', unused_attrs)
      obj
    end

    def get_status_codes
      obj, unused_attrs = StatusCodes.load request(:get_status_codes)
      report_unused_attrs('get_status_codes', unused_attrs)
      obj
    end
  end

  class ApiObject

    class << self;
      attr_accessor :all_attributes
      attr_accessor :fields
      attr_accessor :lists
      attr_accessor :refs
    end

    def self.inherited(base)
      base.all_attributes = []
      base.fields = []
      base.lists = {}
      base.refs = {}
    end

    def self.to_api_name(name)
      name.to_s.gsub(/\?$/, '').camelize(:lower)
    end

    def self.to_attr_name(name)
      name.to_s.gsub(/\?$/, '').underscore
    end

    def self.field_methods(name)
      is_bool = name.to_s.end_with?('?')
      attr_name = to_attr_name(name)
      api_name = to_api_name(name)
      class_eval <<-EOF, __FILE__, __LINE__
        def #{attr_name}#{'?' if is_bool}
          @#{api_name}
        end
        def #{attr_name}=(value)
          @#{api_name} = value
        end
      EOF
    end

    def self.has_fields(*names)
      names.each do |name|
        @all_attributes << to_api_name(name)
        @fields << to_api_name(name)
        field_methods(name)
      end
    end

    def self.has_objects_list(name, klass)
      @all_attributes << to_api_name(name)
      @lists[to_api_name(name)] = klass
      field_methods(name)
    end

    def self.has_object_ref(name, klass)
      @all_attributes << to_api_name(name)
      @refs[to_api_name(name)] = klass
      field_methods(name)
    end

    def self.load(attributes = {})
      obj = self.new
      unused_attrs = []
      attributes.each do |name, value|
        if @fields.include?(name)
          obj.instance_variable_set("@#{name}", value)
        elsif @lists.key?(name)
          unless value.nil?
            var = value.map do |v|
              val, ua = @lists[name].load(v)
              unused_attrs.concat ua
              val
            end
            obj.instance_variable_set("@#{name}", var)
          end
        elsif @refs.key?(name)
          unless value.nil?
            val, ua = @refs[name].load(value)
            unused_attrs.concat ua
            obj.instance_variable_set("@#{name}", val)
          end
        else
          unused_attrs << name
        end
      end
      return obj, unused_attrs
    end

    def to_json(opts = {})
      obj = {}
      self.class.all_attributes.each do |api_name|
        v = instance_variable_get("@#{api_name}")
        obj[api_name] = v
      end
      obj.to_json
    end
  end

  class Cert < ApiObject
    has_fields :subject,
               :commonNames,
               :altNames,
               :notBefore,
               :notAfter,
               :issuerSubject,
               :sigAlg,
               :issuerLabel,
               :revocationInfo,
               :crlURIs,
               :ocspURIs,
               :revocationStatus,
               :crlRevocationStatus,
               :ocspRevocationStatus,
               :sgc?,
               :validationType,
               :issues,
               :sct?,
               :mustStaple,
               :sha1Hash,
               :pinSha256

    def valid?
      issues == 0
    end

    def invalid?
      !valid?
    end
  end

  class ChainCert < ApiObject
    has_fields :subject,
               :label,
               :notBefore,
               :notAfter,
               :issuerSubject,
               :issuerLabel,
               :sigAlg,
               :issues,
               :keyAlg,
               :keySize,
               :keyStrength,
               :revocationStatus,
               :crlRevocationStatus,
               :ocspRevocationStatus,
               :raw,
               :sha1Hash,
               :pinSha256

    def valid?
      issues == 0
    end

    def invalid?
      !valid?
    end
  end

  class Chain < ApiObject
    has_objects_list :certs, ChainCert
    has_fields :issues

    def valid?
      issues == 0
    end

    def invalid?
      !valid?
    end
  end

  class Key < ApiObject
    has_fields :size,
               :strength,
               :alg,
               :debianFlaw?,
               :q

    def insecure?
      debian_flaw? || q == 0
    end

    def secure?
      !insecure?
    end
  end

  class Protocol < ApiObject
    has_fields :id,
               :name,
               :version,
               :v2SuitesDisabled?,
               :q

    def insecure?
      q == 0
    end

    def secure?
      !insecure?
    end

  end

  class Info < ApiObject
    has_fields :engineVersion,
               :criteriaVersion,
               :clientMaxAssessments,
               :maxAssessments,
               :currentAssessments,
               :messages,
               :newAssessmentCoolOff
  end

  class SimClient < ApiObject
    has_fields :id,
               :name,
               :platform,
               :version,
               :isReference?
  end

  class Simulation < ApiObject
    has_object_ref :client, SimClient
    has_fields :errorCode,
               :attempts,
               :protocolId,
               :suiteId,
               :kxInfo

    def success?
      error_code == 0
    end

    def error?
      !success?
    end
  end

  class SimDetails < ApiObject
    has_objects_list :results, Simulation
  end

  class StatusCodes < ApiObject
    has_fields :statusDetails

    def [](name)
      status_details[name]
    end
  end

  class Suite < ApiObject
    has_fields :id,
               :name,
               :cipherStrength,
               :dhStrength,
               :dhP,
               :dhG,
               :dhYs,
               :ecdhBits,
               :ecdhStrength,
               :q

    def insecure?
      q == 0
    end

    def secure?
      !insecure?
    end
  end

  class Suites < ApiObject
    has_objects_list :list, Suite
    has_fields :preference?
  end

  class EndpointDetails < ApiObject
    has_fields :hostStartTime
    has_object_ref :key, Key
    has_object_ref :cert, Cert
    has_object_ref :chain, Chain
    has_objects_list :protocols, Protocol
    has_object_ref :suites, Suites
    has_fields :serverSignature,
               :prefixDelegation?,
               :nonPrefixDelegation?,
               :vulnBeast?,
               :renegSupport,
               :stsResponseHeader,
               :stsMaxAge,
               :stsSubdomains?,
               :pkpResponseHeader,
               :sessionResumption,
               :compressionMethods,
               :supportsNpn?,
               :npnProtocols,
               :sessionTickets,
               :ocspStapling?,
               :staplingRevocationStatus,
               :staplingRevocationErrorMessage,
               :sniRequired?,
               :httpStatusCode,
               :httpForwarding,
               :supportsRc4?,
               :forwardSecrecy,
               :rc4WithModern?
    has_object_ref :sims, SimDetails
    has_fields :heartbleed?,
               :heartbeat?,
               :openSslCcs,
               :poodle?,
               :poodleTls,
               :fallbackScsv?,
               :freak?,
               :hasSct,
               :stsStatus,
               :stsPreload,
               :supportsAlpn,
               :rc4Only,
               :protocolIntolerance,
               :miscIntolerance,
               :openSSLLuckyMinus20,
               :logjam,
               :chaCha20Preference,
               :hstsPolicy,
               :hstsPreloads,
               :hpkpPolicy,
               :hpkpRoPolicy,
               :drownHosts,
               :drownErrors,
               :drownVulnerable
  end

  class Endpoint < ApiObject
    has_fields :ipAddress,
               :serverName,
               :statusMessage,
               :statusDetails,
               :statusDetailsMessage,
               :grade,
               :gradeTrustIgnored,
               :hasWarnings?,
               :isExceptional?,
               :progress,
               :duration,
               :eta,
               :delegation
    has_object_ref :details, EndpointDetails
  end

  class Host < ApiObject
    has_fields :host,
               :port,
               :protocol,
               :isPublic?,
               :status,
               :statusMessage,
               :startTime,
               :testTime,
               :engineVersion,
               :criteriaVersion,
               :cacheExpiryTime
    has_objects_list :endpoints, Endpoint
    has_fields :certHostnames
  end

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'SSL Labs API Client',
        'Description'   => %q{
          This module is a simple client for the SSL Labs APIs, designed for
          SSL/TLS assessment during a penetration test.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Denis Kolegov <dnkolegov[at]gmail.com>',
            'Francois Chagnon' # ssllab.rb author (https://github.com/Shopify/ssllabs.rb)
           ],
        'DefaultOptions' =>
          {
            'RPORT'      => 443,
            'SSL'        => true,
          }
    ))
    register_options(
      [
        OptString.new('HOSTNAME', [true, 'The target hostname']),
        OptInt.new('DELAY', [true, 'The delay in seconds between  API requests', 5]),
        OptBool.new('USECACHE', [true, 'Use cached results (if available), else force live scan', true]),
        OptBool.new('GRADE', [true, 'Output only the hostname: grade', false]),
        OptBool.new('IGNOREMISMATCH', [true, 'Proceed with assessments even when the server certificate doesn\'t match the assessment hostname', true])
      ])
  end

  def report_good(line)
    print_good line
  end

  def report_warning(line)
    print_warning line
  end

  def report_bad(line)
    print_warning line
  end

  def report_status(line)
    print_status line
  end

  def output_endpoint_data(r)
    ssl_protocols = [
      { id: 771, name: "TLS", version: "1.2", secure: true, active: false },
      { id: 770, name: "TLS", version: "1.1", secure: true, active: false },
      { id: 769, name: "TLS", version: "1.0", secure: true, active: false },
      { id: 768, name: "SSL", version: "3.0", secure: false, active: false },
      { id: 2, name: "SSL", version: "2.0", secure: false, active: false }
    ]

    report_status "-----------------------------------------------------------------"
    report_status "Report for #{r.server_name} (#{r.ip_address})"
    report_status "-----------------------------------------------------------------"

    case r.grade.to_s
    when "A+", "A", "A-"
      report_good "Overall rating: #{r.grade}"
    when "B"
      report_warning "Overall rating: #{r.grade}"
    when "C", "D", "E", "F"
      report_bad "Overall rating: #{r.grade}"
    when "M"
      report_bad "Overall rating: #{r.grade} - Certificate name mismatch"
    when "T"
      report_bad "Overall rating: #{r.grade} - Server's certificate is not trusted"
    end

    report_warning "Grade is #{r.grade_trust_ignored}, if trust issues are ignored)" if r.grade.to_s != r.grade_trust_ignored.to_s

    # Supported protocols
    r.details.protocols.each do |i|
      p = ssl_protocols.detect { |x| x[:id] == i.id }
      p.store(:active, true) if p
    end

    ssl_protocols.each do |proto|
      if proto[:active]
        if proto[:secure]
          report_good "#{proto[:name]} #{proto[:version]} - Yes"
        else
          report_bad "#{proto[:name]} #{proto[:version]} - Yes"
        end
      else
        report_good "#{proto[:name]} #{proto[:version]} - No"
      end
    end

    # Renegotioation
    case
    when r.details.reneg_support == 0
      report_warning "Secure renegotiation is not supported"
    when r.details.reneg_support[0] == 1
      report_bad "Insecure client-initiated renegotiation is supported"
    when r.details.reneg_support[1] == 1
      report_good "Secure renegotiation is supported"
    when r.details.reneg_support[2] == 1
      report_warning "Secure client-initiated renegotiation is supported"
    when r.details.reneg_support[3] == 1
      report_warning "Server requires secure renegotiation support"
    end

    # BEAST
    if r.details.vuln_beast?
      report_bad "BEAST attack - Yes"
    else
      report_good "BEAST attack - No"
    end

    # POODLE (SSLv3)
    if r.details.poodle?
      report_bad "POODLE SSLv3 - Vulnerable"
    else
      report_good "POODLE SSLv3 - Not vulnerable"
    end

    # POODLE TLS
    case r.details.poodle_tls
    when -1
      report_warning "POODLE TLS - Test failed"
    when 0
      report_warning "POODLE TLS - Unknown"
    when 1
      report_good "POODLE TLS - Not vulnerable"
    when 2
      report_bad "POODLE TLS - Vulnerable"
    end

    # Downgrade attack prevention
    if r.details.fallback_scsv?
      report_good "Downgrade attack prevention - Yes, TLS_FALLBACK_SCSV supported"
    else
      report_bad "Downgrade attack prevention - No, TLS_FALLBACK_SCSV not supported"
    end

    # Freak
    if r.details.freak?
      report_bad "Freak - Vulnerable"
    else
      report_good "Freak - Not vulnerable"
    end

    # RC4
    if r.details.supports_rc4?
      report_warning "RC4 - Server supports at least one RC4 suite"
    else
      report_good "RC4 - No"
    end

    # RC4 with modern browsers
    report_warning "RC4 is used with modern clients" if r.details.rc4_with_modern?

    # Heartbeat
    if r.details.heartbeat?
      report_status "Heartbeat (extension) - Yes"
    else
      report_status "Heartbeat (extension) - No"
    end

    # Heartbleed
    if r.details.heartbleed?
      report_bad "Heartbleed (vulnerability) - Yes"
    else
      report_good "Heartbleed (vulnerability) - No"
    end

    # OpenSSL CCS
    case r.details.open_ssl_ccs
    when -1
      report_warning "OpenSSL CCS vulnerability (CVE-2014-0224) - Test failed"
    when 0
      report_warning "OpenSSL CCS vulnerability (CVE-2014-0224) - Unknown"
    when 1
      report_good "OpenSSL CCS vulnerability (CVE-2014-0224) - No"
    when 2
      report_bad "OpenSSL CCS vulnerability (CVE-2014-0224) - Possibly vulnerable, but not exploitable"
    when 3
      report_bad "OpenSSL CCS vulnerability (CVE-2014-0224) - Vulnerable and exploitable"
    end

    # Forward Secrecy
    case
    when r.details.forward_secrecy == 0
      report_bad "Forward Secrecy - No"
    when r.details.forward_secrecy[0] == 1
      report_bad "Forward Secrecy - With some browsers"
    when r.details.forward_secrecy[1] == 1
      report_good "Forward Secrecy - With modern browsers"
    when r.details.forward_secrecy[2] == 1
      report_good "Forward Secrecy - Yes (with most browsers)"
    end

    # HSTS
    if r.details.sts_response_header
      str = "Strict Transport Security (HSTS) - Yes"
      if r.details.sts_max_age && r.details.sts_max_age != -1
        str += ":max-age=#{r.details.sts_max_age}"
      end
      str += ":includeSubdomains" if r.details.sts_subdomains?
      report_good str
    else
      report_bad "Strict Transport Security (HSTS) - No"
    end

    # HPKP
    if r.details.pkp_response_header
      report_good "Public Key Pinning (HPKP) - Yes"
    else
      report_warning "Public Key Pinning (HPKP) - No"
    end

    # Compression
    if r.details.compression_methods == 0
      report_good "Compression - No"
    elsif (r.details.session_tickets & 1) != 0
      report_warning "Compression - Yes (Deflate)"
    end

    # Session Resumption
    case r.details.session_resumption
    when 0
      print_status "Session resumption - No"
    when 1
      report_warning "Session resumption - No (IDs assigned but not accepted)"
    when 2
      print_status "Session resumption - Yes"
    end

    # Session Tickets
    case
    when r.details.session_tickets == 0
      print_status "Session tickets - No"
    when r.details.session_tickets[0] == 1
      print_status "Session tickets - Yes"
    when r.details.session_tickets[1] == 1
      report_good "Session tickets - Implementation is faulty"
    when r.details.session_tickets[2] == 1
      report_warning "Session tickets - Server is intolerant to the extension"
    end

    # OCSP stapling
    if r.details.ocsp_stapling?
      print_status "OCSP Stapling - Yes"
    else
      print_status "OCSP Stapling - No"
    end

    # NPN
    if r.details.supports_npn?
      print_status "Next Protocol Negotiation (NPN) - Yes (#{r.details.npn_protocols})"
    else
      print_status "Next Protocol Negotiation (NPN) - No"
    end

    # SNI
    print_status "SNI Required - Yes" if r.details.sni_required?
  end

  def output_grades_only(r)
    r.endpoints.each do |e|
      if e.status_message == "Ready"
        print_status "Server: #{e.server_name} (#{e.ip_address}) - Grade:#{e.grade}"
      else
        print_status "Server: #{e.server_name} (#{e.ip_address} - Status:#{e.status_message}"
      end
    end
  end

  def output_common_info(r)
    return unless r
    print_status "Host: #{r.host}"

    r.endpoints.each do |e|
      print_status "\t  #{e.ip_address}"
    end
  end

  def output_result(r, grade)
    return unless r
    output_common_info(r)
    if grade
      output_grades_only(r)
    else
      r.endpoints.each do |e|
        if e.status_message == "Ready"
          output_endpoint_data(e)
        else
          print_status "#{e.status_message}"
        end
      end
    end
  end

  def output_testing_details(r)
    return unless r.status == "IN_PROGRESS"

    if r.endpoints.length == 1
      print_status "#{r.host} (#{r.endpoints[0].ip_address}) - Progress #{[r.endpoints[0].progress, 0].max}% (#{r.endpoints[0].status_details_message})"
    elsif r.endpoints.length > 1
      in_progress_srv_num = 0
      ready_srv_num = 0
      pending_srv_num = 0
      r.endpoints.each do |e|
        case e.status_message.to_s
        when "In progress"
          in_progress_srv_num += 1
          print_status "Scanned host: #{e.ip_address} (#{e.server_name})- #{[e.progress, 0].max}% complete (#{e.status_details_message})"
        when "Pending"
          pending_srv_num += 1
        when "Ready"
          ready_srv_num += 1
        end
      end
      progress = ((ready_srv_num.to_f / (pending_srv_num + in_progress_srv_num + ready_srv_num)) * 100.0).round(0)
      print_status "Ready: #{ready_srv_num}, In progress: #{in_progress_srv_num}, Pending: #{pending_srv_num}"
      print_status "#{r.host} - Progress #{progress}%"
    end
  end

  def valid_hostname?(hostname)
    hostname =~ /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/
  end

  def run
    delay = datastore['DELAY']
    hostname = datastore['HOSTNAME']
    unless valid_hostname?(hostname)
      print_status "Invalid hostname"
      return
    end

    usecache = datastore['USECACHE']
    grade = datastore['GRADE']

    # Use cached results
    if usecache
      from_cache = 'on'
      start_new = 'off'
    else
      from_cache = 'off'
      start_new = 'on'
    end

    # Ignore mismatch
    ignore_mismatch = datastore['IGNOREMISMATCH'] ? 'on' : 'off'

    api = Api.new
    info = api.info
    print_status "SSL Labs API info"
    print_status "API version: #{info.engine_version}"
    print_status "Evaluation criteria: #{info.criteria_version}"
    print_status "Running assessments: #{info.current_assessments} (max #{info.max_assessments})"

    if api.current_assessments >= api.max_assessments
      print_status "Too many active assessments"
      return
    end

    if usecache
      r = api.analyse(host: hostname, fromCache: from_cache, ignoreMismatch: ignore_mismatch, all: 'done')
    else
      r = api.analyse(host: hostname, startNew: start_new, ignoreMismatch: ignore_mismatch, all: 'done')
    end

    loop do
      case r.status
      when "DNS"
        print_status "Server: #{r.host} - #{r.status_message}"
      when "IN_PROGRESS"
        output_testing_details(r)
      when "READY"
        output_result(r, grade)
        return
      when "ERROR"
        print_error "#{r.status_message}"
        return
      else
        print_error "Unknown assessment status"
        return
      end
      sleep delay
      r = api.analyse(host: hostname, all: 'done')
    end

    rescue RequestRateTooHigh
      print_error "Request rate is too high, please slow down"
    rescue InternalError
      print_error "Service encountered an error, sleep 5 minutes"
    rescue ServiceNotAvailable
      print_error "Service is not available, sleep 15 minutes"
    rescue ServiceOverloaded
      print_error "Service is overloaded, sleep 30 minutes"
    rescue
      print_error "Invalid parameters"
  end
end
