module Msf::DBManager::Web::Page
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
    with_connection {
      wspace = opts.delete(:workspace) || workspace

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

      page = ::Mdm::WebPage.find_or_initialize_by_web_site_id_and_path_and_query(site[:id], path, query)
      page.code     = code
      page.body     = body
      page.headers  = headers
      page.cookie   = opts[:cookie] if opts[:cookie]
      page.auth     = opts[:auth]   if opts[:auth]
      page.mtime    = opts[:mtime]  if opts[:mtime]
      page.ctype    = opts[:ctype]  if opts[:ctype]
      page.location = opts[:location] if opts[:location]
      msf_import_timestamps(opts, page)
      page.save!

      ret[:web_page] = page
    }

  end
end