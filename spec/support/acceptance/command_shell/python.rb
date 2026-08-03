# frozen_string_literal: true

module Acceptance::Session
  PYTHON_SSL_IMAGE = 'ghcr.io/rapid7/metasploit-framework/pyenv@sha256:bc3398ad96f06ac4c9f2a371488b7b75c60eaaa37531da1dcf98ce47b5191fb7'
  PYTHON_SSL_CONTAINER_CMD = '$(command -v podman || command -v docker)'

  PYTHON_MODULE_TESTS = [
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
      module_tests: PYTHON_MODULE_TESTS
    }
  end

  PYTHON_SSL_2_6  = python_ssl_config('2.6.9-no-pip')
  PYTHON_SSL_2_7  = python_ssl_config('2.7.18')
  PYTHON_SSL_3_4  = python_ssl_config('3.4.10')
  PYTHON_SSL_3_13 = python_ssl_config('3.13.13')

  PYTHON = {
    payloads: [
      {
        name: 'python/shell_reverse_tcp',
        extension: '.py',
        platforms: [:linux],
        execute_cmd: ['python', '${payload_path}'],
        generate_options: {
          '-f': 'raw'
        },
        datastore: {
          global: {},
          module: {}
        }
      },
      {
        name: 'cmd/unix/reverse_python',
        extension: '.sh',
        platforms: [:linux],
        execute_cmd: ['sh ${payload_path}'],
        generate_options: {
          '-f': 'raw'
        },
        datastore: {
          global: {},
          module: {}
        }
      },
      {
        name: 'python/shell_bind_tcp',
        extension: '.py',
        platforms: [:linux],
        execute_cmd: ['python', '${payload_path}'],
        generate_options: {
          '-f': 'raw'
        },
        datastore: {
          global: {},
          module: {
            RHOST: '127.0.0.1'
          }
        }
      },
    ],
    module_tests: PYTHON_MODULE_TESTS
  }
end
