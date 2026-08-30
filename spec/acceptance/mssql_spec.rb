# frozen_string_literal: true

require 'acceptance_spec_helper'

RSpec.describe 'MSSQL sessions and MSSQL modules' do
  include_context 'protocol_session_acceptance'

  tests = {
    mssql: {
      target: {
        session_module: 'auxiliary/scanner/mssql/mssql_login',
        type: 'MSSQL',
        platforms: [:linux, :osx, :windows],
        session_info_pattern: /MSSQL #{Regexp.escape(ENV.fetch('MSSQL_USER', 'sa'))} @ \d+\.\d+\.\d+\.\d+/,
        datastore: {
          global: {},
          module: {
            username: ENV.fetch('MSSQL_USER', 'sa'),
            password: ENV.fetch('MSSQL_PASSWORD', 'yourStrong(!)Password'),
            rhost: ENV.fetch('MSSQL_RHOST', '127.0.0.1'),
            rport: ENV.fetch('MSSQL_RPORT', '1433'),
            database: 'master'
          }
        }
      },
      module_tests: [
        {
          name: 'post/test/mssql',
          platforms: [:linux, :osx, :windows],
          targets: [:session],
          skipped: false,
        },
        {
          name: 'auxiliary/scanner/mssql/mssql_hashdump',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Instance Name: "\w+"/,
              ]
            },
          }
        },
        {
          name: 'auxiliary/scanner/mssql/mssql_version',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Version: \d+.\d+.\d+/,
                /Encryption: (?:on|off|unsupported|required|unknown)/
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mssql/mssql_enum',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                'Version:',
                /Microsoft SQL Server \d+.\d+/,
                'Databases on the server:',
                'System Logins on this Server:'
              ]
            },
          }
        },
        {
          name: 'auxiliary/scanner/mssql/mssql_schemadump',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Instance Name: "\w+"/,
                'Microsoft SQL Server Schema',
                'Host:',
                'Port:',
                'Instance:',
                'Version:'
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mssql/mssql_sql',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                'Response',
                'Microsoft SQL Server',
              ]
            },
          }
        },
        {
          name: 'auxiliary/admin/mssql/mssql_sql',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          datastore: { SQL: 'EXEC sp_databases' },
          lines: {
            all: {
              required: [
                'Response',
                'master',
              ]
            },
          }
        }
      ]
    }
  }

  run_protocol_session_tests(tests, features: %w[mssql_session_type])
end
