# frozen_string_literal: true

require 'acceptance_spec_helper'

RSpec.describe 'MySQL sessions and MySQL modules' do
  include_context 'protocol_session_acceptance'

  tests = {
    mysql: {
      target: {
        session_module: 'auxiliary/scanner/mysql/mysql_login',
        type: 'MySQL',
        platforms: [:linux, :osx, :windows],
        session_info_pattern: /MySQL #{Regexp.escape(ENV.fetch('MYSQL_USERNAME', 'root'))} @ \d+\.\d+\.\d+\.\d+/,
        datastore: {
          global: {},
          module: {
            username: ENV.fetch('MYSQL_USERNAME', 'root'),
            password: ENV.fetch('MYSQL_PASSWORD', 'password'),
            rhost: ENV.fetch('MYSQL_RHOST', '127.0.0.1'),
            rport: ENV.fetch('MYSQL_RPORT', '3306'),
          }
        }
      },
      module_tests: [
        {
          name: 'post/test/mysql',
          platforms: [:linux, :osx, :windows],
          targets: [:session],
          skipped: false,
        },
        {
          name: 'auxiliary/scanner/mysql/mysql_hashdump',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Saving HashString as Loot/
              ]
            },
          }
        },
        {
          name: 'auxiliary/scanner/mysql/mysql_version',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /\d+\.\d+\.\d+\.\d+:\d+ is running MySQL \d+.\d+.*/
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mysql/mysql_sql',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /\| \d+.\d+.*/,
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mysql/mysql_enum',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /MySQL Version: \d+.\d+.*/,
              ]
            },
          }
        },
      ]
    }
  }

  run_protocol_session_tests(tests, features: %w[mysql_session_type])
end
