# frozen_string_literal: true

require 'acceptance_spec_helper'

RSpec.describe 'SSH sessions and SSH modules' do
  include_context 'protocol_session_acceptance'

  tests = {
    ssh: {
      target: {
        session_module: 'auxiliary/scanner/ssh/ssh_login',
        type: 'SSH',
        platforms: %i[linux osx windows],
        session_info_pattern: /SSH #{Regexp.escape(ENV.fetch('SSH_USERNAME', 'acceptance_tests_user'))} @ \d+\.\d+\.\d+\.\d+/,
        datastore: {
          global: {},
          module: {
            username: ENV.fetch('SSH_USERNAME', 'acceptance_tests_user'),
            password: ENV.fetch('SSH_PASSWORD', 'acceptance_tests_password'),
            rhost: ENV.fetch('SSH_RHOST', '127.0.0.1'),
            rport: ENV.fetch('SSH_RPORT', '2222'),
          }
        }
      },
      module_tests: [
        {
          name: 'post/test/unix',
          platforms: %i[linux osx],
          targets: [:session],
          skipped: false,
        },
        {
          name: 'auxiliary/scanner/ssh/ssh_version',
          platforms: %i[linux osx windows],
          targets: [:rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /SSH server version: SSH-\d+\.\d+-/,
              ]
            },
          }
        },
      ]
    }
  }

  # SSH shell sessions don't require a feature flag
  run_protocol_session_tests(tests)
end
