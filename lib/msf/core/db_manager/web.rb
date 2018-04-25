module Msf::DBManager::Web
  #
  # Report a Web Form to the database.  WebForm must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+:: the web site object that this page should be associated with
  # +:path+::     the virtual host name for this particular web site
  # +:query+::    the query string that is appended to the path (not valid for GET)
  # +:method+::   the form method, one of GET, POST, or PATH
  # +:params+::   an ARRAY of all parameters and values specified in the form
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  # Duplicate records for a given web_site, path, method, and params combination will be overwritten
  #
  def report_web_form(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    path    = opts[:path]
    meth    = opts[:method].to_s.upcase
    para    = opts[:params]
    quer    = opts[:query].to_s
    site    = nil

    if not (path and meth)
      raise ArgumentError, "report_web_form requires the path and method parameters"
    end

    if not %W{GET POST PATH}.include?(meth)
      raise ArgumentError, "report_web_form requires the method to be one of GET, POST, PATH"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_form was unable to create the associated web site"
      end
    end

    ret = {}

    # Since one of our serialized fields is used as a unique parameter, we must do the final
    # comparisons through ruby and not SQL.

    form = nil
    ::Mdm::WebForm.where(web_site_id: site[:id], path: path, method: meth, query: quer).each do |xform|
      if xform.params == para
        form = xform
        break
      end
    end
    if not form
      form = ::Mdm::WebForm.new
      form.web_site_id = site[:id]
      form.path        = path
      form.method      = meth
      form.params      = para
      form.query       = quer
    end

    msf_import_timestamps(opts, form)
    form.save!
    ret[:web_form] = form
  }
  end

  #
  # Report a Web Page to the database.  WebPage must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+:: the web site object that this page should be associated with
  # +:path+::     the virtual host name for this particular web site
  # +:code+::     the http status code from requesting this page
  # +:headers+::  this is a HASH of headers (lowercase name as key) of ARRAYs of values
  # +:body+::     the document body of the server response
  # +:query+::    the query string after the path
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  # These values will be used to create new host, service, and web_site records
  #
  # opts can contain
  # +:cookie+::   the Set-Cookie headers, merged into a string
  # +:auth+::     the Authorization headers, merged into a string
  # +:ctype+::    the Content-Type headers, merged into a string
  # +:mtime+::    the timestamp returned from the server of the last modification time
  # +:location+:: the URL that a redirect points to
  #
  # Duplicate records for a given web_site, path, and query combination will be overwritten
  #
  def report_web_page(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    path    = opts[:path]
    code    = opts[:code].to_i
    body    = opts[:body].to_s
    query   = opts[:query].to_s
    headers = opts[:headers]
    site    = nil

    if not (path and code and body and headers)
      raise ArgumentError, "report_web_page requires the path, query, code, body, and headers parameters"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_page was unable to create the associated web site"
      end
    end

    ret = {}

    page = ::Mdm::WebPage.where(web_site_id: site[:id], path: path, query: query).first_or_initialize
    page.code     = code
    page.body     = body
    page.headers  = headers
    page.cookie   = opts[:cookie] if opts[:cookie]
    page.auth     = opts[:auth]   if opts[:auth]
    page.mtime    = opts[:mtime]  if opts[:mtime]


    if opts[:ctype].blank? || opts[:ctype] == [""]
      page.ctype = ""
    else
      page.ctype = opts[:ctype]
    end

    page.location = opts[:location] if opts[:location]

    msf_import_timestamps(opts, page)
    page.save!

    ret[:web_page] = page
  }

  end

  #
  # WMAP
  # Support methods
  #

  #
  # Report a Web Site to the database.  WebSites must be tied to an existing Service
  #
  # opts MUST contain
  # +:service+:: the service object this site should be associated with
  # +:vhost+::   the virtual host name for this particular web site`
  #
  # If +:service+ is NOT specified, the following values are mandatory
  # +:host+:: the ip address of the server hosting the web site
  # +:port+:: the port number of the associated web site
  # +:ssl+::  whether or not SSL is in use on this port
  #
  # These values will be used to create new host and service records
  #
  # opts can contain
  # +:options+:: a hash of options for accessing this particular web site
  # +:info+:: if present, report the service with this info
  #
  # Duplicate records for a given host, port, vhost combination will be overwritten
  #
  def report_web_site(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection { |conn|
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    vhost  = opts.delete(:vhost)

    addr = nil
    port = nil
    name = nil
    serv = nil
    info = nil

    if opts[:service] and opts[:service].kind_of?(::Mdm::Service)
      serv = opts[:service]
    else
      addr = opts[:host]
      port = opts[:port]
      name = opts[:ssl] ? 'https' : 'http'
      info = opts[:info]
      if not (addr and port)
        raise ArgumentError, "report_web_site requires service OR host/port/ssl"
      end

      # Force addr to be the address and not hostname
      addr = Rex::Socket.getaddress(addr, true)
    end

    ret = {}

    host = serv ? serv.host : find_or_create_host(
      :workspace => wspace,
      :host      => addr,
      :state     => Msf::HostState::Alive
    )

    if host.name.to_s.empty?
      host.name = vhost
      host.save!
    end

    serv = serv ? serv : find_or_create_service(
      :workspace => wspace,
      :host      => host,
      :port      => port,
      :proto     => 'tcp',
      :state     => 'open'
    )

    # Change the service name if it is blank or it has
    # been explicitly specified.
    if opts.keys.include?(:ssl) or serv.name.to_s.empty?
      name = opts[:ssl] ? 'https' : 'http'
      serv.name = name
    end
    # Add the info if it's there.
    unless info.to_s.empty?
      serv.info = info
    end
    serv.save! if serv.changed?
=begin
    host.updated_at = host.created_at
    host.state      = HostState::Alive
    host.save!
=end

    vhost ||= host.address
    site = ::Mdm::WebSite.where(vhost: vhost, service_id: serv[:id]).first_or_initialize
    site.options = opts[:options] if opts[:options]

    # XXX:
    msf_import_timestamps(opts, site)
    site.save!

    ret[:web_site] = site
  }
  end

  #
  # Report a Web Vuln to the database.  WebVuln must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+::  the web site object that this page should be associated with
  # +:path+::      the virtual host name for this particular web site
  # +:query+::     the query string appended to the path (not valid for GET method flaws)
  # +:method+::    the form method, one of GET, POST, or PATH
  # +:params+::    an ARRAY of all parameters and values specified in the form
  # +:pname+::     the specific field where the vulnerability occurs
  # +:proof+::     the string showing proof of the vulnerability
  # +:risk+::      an INTEGER value from 0 to 5 indicating the risk (5 is highest)
  # +:name+::      the string indicating the type of vulnerability
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  #
  # Duplicate records for a given web_site, path, method, pname, and name
  # combination will be overwritten
  #
  def report_web_vuln(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    path    = opts[:path]
    meth    = opts[:method]
    para    = opts[:params] || []
    quer    = opts[:query].to_s
    pname   = opts[:pname]
    proof   = opts[:proof]
    risk    = opts[:risk].to_i
    name    = opts[:name].to_s.strip
    blame   = opts[:blame].to_s.strip
    desc    = opts[:description].to_s.strip
    conf    = opts[:confidence].to_i
    cat     = opts[:category].to_s.strip
    payload = opts[:payload].to_s
    owner   = opts[:owner] ? opts[:owner].shortname : nil


    site    = nil

    if not (path and meth and proof and pname)
      raise ArgumentError, "report_web_vuln requires the path, method, proof, risk, name, params, and pname parameters. Received #{opts.inspect}"
    end

    if not %W{GET POST PATH}.include?(meth)
      raise ArgumentError, "report_web_vuln requires the method to be one of GET, POST, PATH. Received '#{meth}'"
    end

    if risk < 0 or risk > 5
      raise ArgumentError, "report_web_vuln requires the risk to be between 0 and 5 (inclusive). Received '#{risk}'"
    end

    if conf < 0 or conf > 100
      raise ArgumentError, "report_web_vuln requires the confidence to be between 1 and 100 (inclusive). Received '#{conf}'"
    end

    if cat.empty?
      raise ArgumentError, "report_web_vuln requires the category to be a valid string"
    end

    if name.empty?
      raise ArgumentError, "report_web_vuln requires the name to be a valid string"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_form was unable to create the associated web site"
      end
    end

    ret = {}

    meth = meth.to_s.upcase

    vuln = ::Mdm::WebVuln.where(web_site_id: site[:id], path: path, method: meth, pname: pname, name: name, category: cat, query: quer).first_or_initialize
    vuln.name     = name
    vuln.risk     = risk
    vuln.params   = para
    vuln.proof    = proof.to_s
    vuln.category = cat
    vuln.blame    = blame
    vuln.description = desc
    vuln.confidence  = conf
    vuln.payload = payload
    vuln.owner   = owner

    msf_import_timestamps(opts, vuln)
    vuln.save!

    ret[:web_vuln] = vuln
  }
  end
end