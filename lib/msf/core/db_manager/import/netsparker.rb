require 'rex/parser/netsparker_xml'

module Msf::DBManager::Import::Netsparker
  # Process NetSparker XML
  def import_netsparker_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || args[:workspace]
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    addr = nil
    parser = Rex::Parser::NetSparkerXMLStreamParser.new
    parser.on_found_vuln = Proc.new do |vuln|
      data = {:workspace => wspace}

      # Parse the URL
      url  = vuln['url']
      return if not url

      # Crack the URL into a URI
      uri = URI(url) rescue nil
      return if not uri

      # Resolve the host and cache the IP
      if not addr
        baddr = Rex::Socket.addr_aton(uri.host) rescue nil
        if baddr
          addr = Rex::Socket.addr_ntoa(baddr)
          yield(:address, addr) if block
        end
      end

      # Bail early if we have no IP address
      if not addr
        raise Interrupt, "Not a valid IP address"
      end

      if bl.include?(addr)
        raise Interrupt, "IP address is on the blacklist"
      end

      data[:host]  = addr
      data[:vhost] = uri.host
      data[:port]  = uri.port
      data[:ssl]   = (uri.scheme == "ssl")

      body = nil
      # First report a web page
      if vuln['response']
        headers = {}
        code    = 200
        head,body = vuln['response'].to_s.split(/\r?\n\r?\n/, 2)
        if body

          if head =~ /^HTTP\d+\.\d+\s+(\d+)\s*/
            code = $1.to_i
          end

          headers = {}
          head.split(/\r?\n/).each do |line|
            hname,hval = line.strip.split(/\s*:\s*/, 2)
            next if hval.to_s.strip.empty?
            headers[hname.downcase] ||= []
            headers[hname.downcase] << hval
          end

          info = {
            :path     => uri.path,
            :query    => uri.query,
            :code     => code,
            :body     => body,
            :headers  => headers,
            :task     => args[:task]
          }
          info.merge!(data)

          if headers['content-type']
            info[:ctype] = headers['content-type'][0]
          end

          if headers['set-cookie']
            info[:cookie] = headers['set-cookie'].join("\n")
          end

          if headers['authorization']
            info[:auth] = headers['authorization'].join("\n")
          end

          if headers['location']
            info[:location] = headers['location'][0]
          end

          if headers['last-modified']
            info[:mtime] = headers['last-modified'][0]
          end

          # Report the web page to the database
          report_web_page(info)

          yield(:web_page, url) if block
        end
      end # End web_page reporting


      details = netsparker_vulnerability_map(vuln)

      method = netsparker_method_map(vuln)
      pname  = netsparker_pname_map(vuln)
      params = netsparker_params_map(vuln)

      proof  = ''

      if vuln['info'] and vuln['info'].length > 0
        proof << vuln['info'].map{|x| "#{x[0]}: #{x[1]}\n" }.join + "\n"
      end

      if proof.empty?
        if body
          proof << body + "\n"
        else
          proof << vuln['response'].to_s + "\n"
        end
      end

      if params.empty? and pname
        params = [[pname, vuln['vparam_name'].to_s]]
      end

      info = {
        # XXX: There is a :request attr in the model, but report_web_vuln
        # doesn't seem to know about it, so this gets ignored.
        #:request  => vuln['request'],
        :path        => uri.path,
        :query       => uri.query,
        :method      => method,
        :params      => params,
        :pname       => pname.to_s,
        :proof       => proof,
        :risk        => details[:risk],
        :name        => details[:name],
        :blame       => details[:blame],
        :category    => details[:category],
        :description => details[:description],
        :confidence  => details[:confidence],
        :task        => args[:task]
      }
      info.merge!(data)

      next if vuln['type'].to_s.empty?

      report_web_vuln(info)
      yield(:web_vuln, url) if block
    end

    # We throw interrupts in our parser when the job is hopeless
    begin
      REXML::Document.parse_stream(data, parser)
    rescue ::Interrupt => e
      wlog("The netsparker_xml_import() job was interrupted: #{e}")
    end
  end

  # Process a NetSparker XML file
  def import_netsparker_xml_file(args={})
    filename = args[:filename]

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_netsparker_xml(args.merge(:data => data))
  end

  def netsparker_method_map(vuln)
    case vuln['vparam_type']
    when "FullQueryString"
      "GET"
    when "Querystring"
      "GET"
    when "Post"
      "POST"
    when "RawUrlInjection"
      "GET"
    else
      "GET"
    end
  end

  def netsparker_params_map(vuln)
    []
  end

  def netsparker_pname_map(vuln)
    case vuln['vparam_name']
    when "URI-BASED", "Query Based"
      "PATH"
    else
      vuln['vparam_name']
    end
  end

  def netsparker_vulnerability_map(vuln)
    res = {
      :risk => 1,
      :name  => 'Information Disclosure',
      :blame => 'System Administrator',
      :category => 'info',
      :description => "This is an information leak",
      :confidence => 100
    }

    # Risk is a value from 1-5 indicating the severity of the issue
    #	Examples: 1, 4, 5

    # Name is a descriptive name for this vulnerability.
    #	Examples: XSS, ReflectiveXSS, PersistentXSS

    # Blame indicates who is at fault for the vulnerability
    #	Examples: App Developer, Server Developer, System Administrator

    # Category indicates the general class of vulnerability
    #	Examples: info, xss, sql, rfi, lfi, cmd

    # Description is a textual summary of the vulnerability
    #	Examples: "A reflective cross-site scripting attack"
    #             "The web server leaks the internal IP address"
    #             "The cookie is not set to HTTP-only"

    #
    # Confidence is a value from 1 to 100 indicating how confident the
    # software is that the results are valid.
    #	Examples: 100, 90, 75, 15, 10, 0

    case vuln['type'].to_s
    when "ApacheDirectoryListing"
      res = {
        :risk => 1,
        :name  => 'Directory Listing',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ApacheMultiViewsEnabled"
      res = {
        :risk => 1,
        :name  => 'Apache MultiViews Enabled',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ApacheVersion"
      res = {
        :risk => 1,
        :name  => 'Web Server Version',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PHPVersion"
      res = {
        :risk => 1,
        :name  => 'PHP Module Version',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "AutoCompleteEnabled"
      res = {
        :risk => 1,
        :name  => 'Form AutoComplete Enabled',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "CookieNotMarkedAsHttpOnly"
      res = {
        :risk => 1,
        :name  => 'Cookie Not HttpOnly',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "EmailDisclosure"
      res = {
        :risk => 1,
        :name  => 'Email Address Disclosure',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ForbiddenResource"
      res = {
        :risk => 1,
        :name  => 'Forbidden Resource',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "FileUploadFound"
      res = {
        :risk => 1,
        :name  => 'File Upload Form',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PasswordOverHTTP"
      res = {
        :risk => 2,
        :name  => 'Password Over HTTP',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "MySQL5Identified"
      res = {
        :risk => 1,
        :name  => 'MySQL 5 Identified',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleInternalWindowsPathLeakage"
      res = {
        :risk => 1,
        :name  => 'Path Leakage - Windows',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleInternalUnixPathLeakage"
      res = {
        :risk => 1,
        :name  => 'Path Leakage - Unix',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleXSS", "LowPossibilityPermanentXSS", "XSS", "PermanentXSS"
      conf = 100
      conf = 25  if vuln['type'].to_s == "LowPossibilityPermanentXSS"
      conf = 50  if vuln['type'].to_s == "PossibleXSS"
      res = {
        :risk => 3,
        :name  => 'Cross-Site Scripting',
        :blame => 'App Developer',
        :category => 'xss',
        :description => "",
        :confidence => conf
      }

    when "ConfirmedBlindSQLInjection", "ConfirmedSQLInjection", "HighlyPossibleSqlInjection", "DatabaseErrorMessages"
      conf = 100
      conf = 90  if vuln['type'].to_s == "HighlyPossibleSqlInjection"
      conf = 25  if vuln['type'].to_s == "DatabaseErrorMessages"
      res = {
        :risk => 5,
        :name  => 'SQL Injection',
        :blame => 'App Developer',
        :category => 'sql',
        :description => "",
        :confidence => conf
      }
    else
    conf = 100
    res = {
      :risk => 1,
      :name  => vuln['type'].to_s,
      :blame => 'App Developer',
      :category => 'info',
      :description => "",
      :confidence => conf
    }
    end

    res
  end
end
