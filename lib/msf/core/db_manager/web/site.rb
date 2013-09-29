module Msf::DBManager::Web::Site
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
    with_connection {
      wspace = opts.delete(:workspace) || workspace
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
      site = ::Mdm::WebSite.find_or_initialize_by_vhost_and_service_id(vhost, serv[:id])
      site.options = opts[:options] if opts[:options]

      # XXX:
      msf_import_timestamps(opts, site)
      site.save!

      ret[:web_site] = site
    }
  end
end