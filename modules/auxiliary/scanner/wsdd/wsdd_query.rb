##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'WS-Discovery Information Discovery',
      'Description' => %q{
        Discover information from Web Services Dynamic Discovery (WS-Discovery)
        enabled systems.
      },
      'Author'      => 'bcoles',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'https://msdn.microsoft.com/en-us/library/windows/desktop/bb513684(v=vs.85).aspx'],
          ['URL', 'http://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pd'],
          ['URL', 'https://en.wikipedia.org/wiki/Web_Services_for_Devices'],
          ['URL', 'https://en.wikipedia.org/wiki/WS-Discovery'],
          ['URL', 'https://en.wikipedia.org/wiki/Zero-configuration_networking#WS-Discovery']
        ]
    )
    register_options [
      Opt::RPORT(3702),
      OptAddressRange.new('RHOSTS', [true, 'The multicast address or CIDR range of targets to query', '239.255.255.250'])
    ]
  end

  def rport
    datastore['RPORT']
  end

  def wsdd_probe
    probe = '<?xml version="1.0" encoding="utf-8" ?>'
    probe << '<soap:Envelope'
    probe << ' xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
    probe << ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    probe << ' xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
    probe << ' xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">'

    probe << '<soap:Header>'
    # WS-Discovery
    probe << '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
    # Action (Probe)
    probe << "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
    # Message identifier (unique GUID)
    probe << "<wsa:MessageID>urn:uuid:#{SecureRandom.uuid}</wsa:MessageID>"
    probe << '</soap:Header>'

    probe << '<soap:Body>'
    probe << '<wsd:Probe/>' # WS-Discovery type (blank)
    probe << '</soap:Body>'
    probe << '</env:Envelope>'

    probe
  end

  def scanner_prescan(batch)
    print_status "Sending WS-Discovery probe to #{batch.length} hosts"
    @results = {}
  end

  def scan_host(ip)
    vprint_status "#{ip}:#{rport} - Sending WS-Discovery probe"
    scanner_send wsdd_probe, ip, datastore['RPORT']
  end

  def scanner_postscan(_batch)
    if @results.empty?
      print_status 'No WS-Discovery endpoints found.'
      return
    end

    found = {}
    @results.each_pair do |ip, responses|
      responses.uniq.each do |res|
        found[ip] ||= {}
        next if found[ip][res]

        response_info = parse_wsdd_response res

        if response_info.nil?
          print_error "#{ip} responded with malformed data"
          next
        end

        msg = []
        msg << "Address: #{response_info['Address']}"
        msg << "Types: #{response_info['Types'].to_s.split(/\s+/).join(', ')}"
        msg << "Vendor Extensions: #{response_info['VendorExtension']}" unless response_info['VendorExtension'].nil?

        print_good "#{ip} responded with:\n#{msg.join("\n")}"

        report_service(host: ip, port: rport, proto: 'udp', name: 'wsdd', info: response_info)
        found[ip][res] = true
      end
    end
  end

  def parse_wsdd_response(wsdd_res)
    info = {}

    # Validate ProbeMatches SOAP response contains a ProbeMatch
    begin
      soap = ::Nokogiri::XML wsdd_res
      return nil if soap.xpath('//soap:Body//wsd:ProbeMatches//wsd:ProbeMatch').empty?
    rescue
      return nil
    end

    # Convert SOAP response to Hash
    begin
      res = Hash.from_xml wsdd_res
    rescue REXML::ParseException
      return nil
    end

    # Use the first ProbeMatch
    probe_match = res['Envelope']['Body']['ProbeMatches'].first
    return nil unless probe_match[0].eql? 'ProbeMatch'
    return nil if probe_match[1].nil? || probe_match[1].empty?
    match = probe_match[1]

    # Device Address
    info['Address'] = match['XAddrs'] || ''

    # Device Types
    info['Types'] = match['Types'] || ''

    # Optional vendor extensions
    unless match['VendorExtension'].nil? || match['VendorExtension'].empty?
      info['VendorExtension'] = match['VendorExtension']
    end

    info
  end
end
