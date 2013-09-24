module Msf::DBManager::Web::Vuln
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
      wspace = opts.delete(:workspace) || workspace

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

      vuln = ::Mdm::WebVuln.find_or_initialize_by_web_site_id_and_path_and_method_and_pname_and_name_and_category_and_query(site[:id], path, meth, pname, name, cat, quer)
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