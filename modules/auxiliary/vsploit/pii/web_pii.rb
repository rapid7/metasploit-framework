##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  #
  # This module acts as an compromised webserver distributing PII Data
  #
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::PII

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'VSploit Web PII',
      'Description'    => 'This module emulates a webserver leaking PII data',
      'License'        => MSF_LICENSE,
      'Author'         => 'MJC',
      'References' =>
      [
        [ 'URL', 'https://blog.rapid7.com/2011/06/02/vsploit--virtualizing-exploitation-attributes-with-metasploit-framework']
      ],
      'DefaultOptions' => { 'HTTP::server_name' => 'IIS'}
      ))
    register_options(
        [
          OptBool.new('META_REFRESH', [ false, "Set page to auto refresh.", false]),
          OptInt.new('REFRESH_TIME', [ false, "Set page refresh interval.", 15]),
          OptInt.new('ENTRIES', [ false, "PII Entry Count", 1000])
        ])
  end


  def create_page
    # Webpage Title
    title = "vSploit PII Webserver"
    sheep = <<-EOS
 __________
< baaaaah! >
 ---------
     \\
      \\
          ,@;@,
         ;@;@( \\@;@;@;@;@;@,
         /x  @\\_|@;@;@;@;@;@;,
        /    )@:@;@;@;@;@;@;@|)
        *---;@;@;@;@;@;@;@;@;
               ';@;\;@;\;@;@
                || |   \\ (
                || |   // /
                // (  // /
               ~~~~~ ~~~~

EOS
    page = ""
    page << "<html>\n<head>\n"

    if datastore['META_REFRESH']
      page << "<meta http-equiv=\"refresh\" content=\"#{datastore['REFRESH_TIME']}\">\n"
    end

    page << "<title>#{title}</title>\n</head>\n<body>\n"
    page << "<pre>\n"
    page << sheep
    page << "Data Creation by: #{title}\n"
    page << "Entries Per Page: #{datastore['ENTRIES']}\n"

    if datastore['META_REFRESH']
      page << "Refresh Interval: #{datastore['REFRESH_TIME']} Seconds\n"
    end

    # Start creating PII data
    pii = create_pii()
    page << "\n"
    page << pii
    page << "</pre>\n</body>\n</html>"
    page
  end

  def on_request_uri(cli,request)
    # Transmit the response to the client
    res = create_page()
    print_status("Leaking PII...")
    send_response(cli, res, { 'Content-Type' => 'text/html' })
  end

  def run
    exploit()
  end
end
