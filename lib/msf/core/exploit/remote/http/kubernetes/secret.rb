# -*- coding: binary -*-

# Secret types:
#   https://kubernetes.io/docs/concepts/configuration/secret/
module Msf::Exploit::Remote::HTTP::Kubernetes::Secret
  # Arbitrary user-defined data
  Opaque = 'Opaque'

  # service account token
  ServiceAccountToken = 'kubernetes.io/service-account-token'

  # serialized ~/.dockercfg file
  DockerConfiguration = 'kubernetes.io/dockercfg'

  # serialized ~/.docker/config.json file
  DockerConfigurationJson = 'kubernetes.io/dockerconfigjson'

  # credentials for basic authentication
  BasicAuth = 'kubernetes.io/basic-auth'

  # credentials for SSH authentication
  SSHAuth = 'kubernetes.io/ssh-auth'

  # data for a TLS client or server
  TLSAuth = 'kubernetes.io/tls'

  # bootstrap token data
  BootstrapTokenData = 'bootstrap.kubernetes.io/token'
end
