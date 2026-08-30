# frozen_string_literal: true

require 'acceptance_spec_helper'

RSpec.describe 'Postgres sessions and postgres modules' do
  include_context 'protocol_session_acceptance'

  tests = {
    postgres: {
      target: {
        session_module: 'auxiliary/scanner/postgres/postgres_login',
        type: 'PostgreSQL',
        platforms: [:linux, :osx, :windows],
        session_info_pattern: /PostgreSQL #{Regexp.escape(ENV.fetch('POSTGRES_USERNAME', 'postgres'))} @ \d+\.\d+\.\d+\.\d+/,
        datastore: {
          global: {},
          module: {
            username: ENV.fetch('POSTGRES_USERNAME', 'postgres'),
            password: ENV.fetch('POSTGRES_PASSWORD', 'password'),
            rhost: ENV.fetch('POSTGRES_RHOST', '127.0.0.1'),
            rport: ENV.fetch('POSTGRES_RPORT', '5432'),
          }
        }
      },
      module_tests: [
        {
          name: 'post/test/postgres',
          platforms: [:linux, :osx, :windows],
          targets: [:session],
          skipped: false,
        },
        {
          name: 'auxiliary/scanner/postgres/postgres_hashdump',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                ' Username  Hash',
                ' --------  ----',
                # postgres  SCRAM-SHA-256$4096:...
                / postgres  \w+/
              ]
            },
          }
        },
        {
          name: 'auxiliary/scanner/postgres/postgres_version',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Version PostgreSQL \d+.\d+/
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/postgres/postgres_readfile',
          platforms: [:linux],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              # Module reads /etc/passwd by default
              required: [
                /root:x:\d+:\d+:root:/,
                /postgres:x:\d+:\d+::/
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/postgres/postgres_sql',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                "Query Text: 'select version()'",
                /PostgreSQL \d+.\d+/,
              ]
            },
          }
        }
      ]
    }
  }

  run_protocol_session_tests(tests, features: %w[postgresql_session_type])
end
