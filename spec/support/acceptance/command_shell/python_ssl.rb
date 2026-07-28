# frozen_string_literal: true

module Acceptance::Session
  PYTHON_SSL_IMAGE = 'public.ecr.aws/n5b4u6h0/zerosteiner/pyenv@sha256:e686265001ee43333f14c896d8362970e816c5a7c661a6fa7e37a90770c9108a'
  PYTHON_SSL_CONTAINER_CMD = '$(command -v podman || command -v docker)'

  PYTHON_SSL_MODULE_TESTS = [
    {
      name: 'post/test/unix',
      platforms: [
        :linux,
        :osx,
        [
          :windows,
          {
            skip: true,
            reason: 'Unix only test'
          }
        ]
      ],
      skipped: false,
      lines: {
        linux: { known_failures: [] },
        osx:   { known_failures: [] },
        windows: { known_failures: [] }
      }
    }
  ].freeze

  def self.python_ssl_config(pyenv_version)
    image = PYTHON_SSL_IMAGE
    runtime = PYTHON_SSL_CONTAINER_CMD

    {
      payloads: [
        {
          name: 'python/shell_reverse_tcp_ssl',
          extension: '.py',
          platforms: [:linux],
          execute_cmd: [
            'bash', '-c',
            "#{runtime} run --rm --network host -v \${payload_path}:\${payload_path}:Z -e PYENV_VERSION=#{pyenv_version} #{image} python \${payload_path}"
          ],
          generate_options: {
            '-f': 'raw'
          },
          datastore: {
            global: {},
            module: {}
          }
        },
        {
          name: 'cmd/unix/reverse_python_ssl',
          extension: '.sh',
          platforms: [:linux],
          execute_cmd: [
            'bash', '-c',
            "#{runtime} run --rm --network host -v \${payload_path}:\${payload_path}:Z -e PYENV_VERSION=#{pyenv_version} #{image} sh \${payload_path}"
          ],
          generate_options: {
            '-f': 'raw'
          },
          datastore: {
            global: {},
            module: {}
          }
        }
      ],
      module_tests: PYTHON_SSL_MODULE_TESTS
    }
  end

  PYTHON_SSL_2_6  = python_ssl_config('2.6.9-no-pip')
  PYTHON_SSL_2_7  = python_ssl_config('2.7.18')
  PYTHON_SSL_3_4  = python_ssl_config('3.4.10')
  PYTHON_SSL_3_13 = python_ssl_config('3.13.7')
end
