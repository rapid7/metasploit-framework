module Msf::DBManager::Web::Form
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
      wspace = opts.delete(:workspace) || workspace

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
      ::Mdm::WebForm.find_all_by_web_site_id_and_path_and_method_and_query(site[:id], path, meth, quer).each do |xform|
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
end