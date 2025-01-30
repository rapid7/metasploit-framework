require 'msf/core'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Subdomain Backup File Brute Force Scanner',
      'Description' => 'This module attempts to find backup files on a list of subdomains via brute force, with improved false-positive detection.',
      'Author'      => ['Parag Bagul'],  # Updated author name
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('DOMAIN_LIST', [true, 'File containing list of subdomains to scan']),
        OptString.new('WORDLIST', [true, 'File containing backup file names to brute-force']),
        Opt::RPORT(80), # Target port (80 for HTTP, 443 for HTTPS)
        OptBool.new('SSL', [false, 'Negotiate SSL/TLS for outgoing connections', false]),
        OptInt.new('THREADS', [true, 'Number of concurrent threads', 10]),
        OptInt.new('MIN_SIZE', [true, 'Minimum file size in bytes to consider (e.g., 5000 for 5KB)', 5000]),
        OptString.new('USER_AGENT', [false, 'Custom User-Agent header for requests',
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'])
      ]
    )
  end

  def run_host(ip)
    domain_list = File.read(datastore['DOMAIN_LIST']).split("\n").map(&:strip)
    wordlist = File.read(datastore['WORDLIST']).split("\n").map(&:strip)
    min_size = datastore['MIN_SIZE']
    user_agent = datastore['USER_AGENT'] # Get the user agent from datastore

    domain_list.each do |subdomain|
      wordlist.each do |backup_file|
        begin
          # Check if SSL is enabled to choose between HTTP and HTTPS
          protocol = datastore['SSL'] ? 'https' : 'http'
          port = datastore['RPORT']
          full_url = "#{protocol}://#{subdomain}:#{port}/#{backup_file}"

          print_status("Checking #{full_url} ...")

          # Send the HTTP request with the custom User-Agent
          res = send_request_cgi({
            'uri'    => "/#{backup_file}",
            'method' => 'GET',
            'rhost'  => subdomain,
            'rport'  => port,
            'ssl'    => datastore['SSL'],
            'headers' => {
              'User-Agent' => user_agent # Set the custom User-Agent
            }
          }, 10)

          # Handle response and avoid false positives
          if res
            print_status("Status Code: #{res.code}")

            # Avoid redirects
            if [301, 302].include?(res.code)
              print_error("Redirect detected: #{full_url} (Status: #{res.code})")
              next
            end

            # Check if the response has a content length and valid size
            content_length = res.headers['Content-Length'] ? res.headers['Content-Length'].to_i : 0
            if content_length < min_size
              print_error("File too small: #{full_url} (Size: #{content_length} bytes)")
              next
            end

            # Check for valid MIME types (e.g., ZIP, TAR, etc.)
            content_type = res.headers['Content-Type']
            unless content_type &&
                   (content_type.include?('application/zip') ||
                    content_type.include?('application/x-tar') ||
                    content_type.include?('application/sql') ||
                    content_type.include?('application/octet-stream'))
              print_error("Invalid MIME Type: #{full_url} (MIME: #{content_type})")
              next
            end

            # If status code 200 and valid size and MIME, mark as a valid file
            if res.code == 200
              print_good("Found valid backup file: #{full_url} (Status: 200, Size: #{content_length} bytes, MIME: #{content_type})")
            else
              print_error("Not Found: #{full_url} (Status: #{res.code})")
            end
          else
            print_error("No Response: #{full_url}")
          end

        rescue ::SocketError, ::Rex::ConnectionError => e
          print_error("Error: #{subdomain}: #{e.message}")
          next
        end
      end
    end
  end
end
