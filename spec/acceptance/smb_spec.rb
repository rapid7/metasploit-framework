# frozen_string_literal: true

require 'acceptance_spec_helper'

RSpec.describe 'SMB sessions and SMB modules' do
  include_context 'protocol_session_acceptance'

  tests = {
    smb: {
      target: {
        session_module: 'auxiliary/scanner/smb/smb_login',
        type: 'SMB',
        platforms: [:linux, :osx, :windows],
        session_info_pattern: /SMB #{Regexp.escape(ENV.fetch('SMB_USERNAME', 'acceptance_tests_user'))} @ \d+\.\d+\.\d+\.\d+/,
        datastore: {
          global: {},
          module: {
            username: ENV.fetch('SMB_USERNAME', 'acceptance_tests_user'),
            password: ENV.fetch('SMB_PASSWORD', 'acceptance_tests_password'),
            rhost: ENV.fetch('SMB_RHOST', '127.0.0.1'),
            rport: ENV.fetch('SMB_RPORT', '445'),
          }
        }
      },
      module_tests: [
        {
          name: 'post/test/smb',
          platforms: [:linux, :osx, :windows],
          targets: [:session],
          skipped: false,
        },
        {
          name: 'auxiliary/scanner/smb/smb_lookupsid',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          datastore: { 'MinRID' => 500, 'MaxRID' => 1001 },
          lines: {
            all: {
              required: [
                'PIPE(lsarpc) LOCAL',
                /User( *)(Administrator|nobody)/,
                /Group( *)(None|Domain (Admins|Users|Guests|Computers))/,
              ],
            },
          }
        },
        {
          name: 'auxiliary/scanner/smb/smb_enumusers',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                'acceptance_tests_user',
              ],
            },
          }
        },
        {
          name: 'auxiliary/scanner/smb/pipe_auditor',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Pipes: (\\([a-zA-Z]*)(, )?)*/,
              ],
              known_failures: [
                /Inaccessible named pipe:/,
                /The server responded with an unexpected status code: STATUS_OBJECT_NAME_NOT_FOUND/,
              ]
            },
          }
        },
        {
          name: 'auxiliary/scanner/smb/smb_enumshares',
          platforms: [:linux, :osx, :windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                'modifiable - (DISK)',
                'readonly - (DISK)',
                'IPC$ - (IPC|SPECIAL) IPC Service',
              ],
            },
          }
        },
        {
          name: 'auxiliary/scanner/smb/smb_version',
          platforms: [:linux, :osx, :windows],
          targets: [:rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /SMB Detected \(versions:.*\) \(preferred dialect:.*\)/,
              ]
            },
          }
        },
      ]
    }
  }

  # Build a v2/v3-only variant: copy the smb target/module_tests, inject SMB::ProtocolVersion
  # into every datastore, and tighten the smb_version assertions.
  tests[:smb_v2] = tests[:smb].merge(
    target: tests[:smb][:target].merge(
      datastore: tests[:smb][:target][:datastore].merge(
        module: tests[:smb][:target][:datastore][:module].merge('SMB::ProtocolVersion' => '2,3')
      )
    ),
    module_tests: tests[:smb][:module_tests].map do |test|
      if test[:name] == 'auxiliary/scanner/smb/smb_version'
        test.merge(
          datastore: (test[:datastore] || {}).merge('SMB::ProtocolVersion' => '2,3'),
          lines: {
            all: {
              required: [
                /SMB Detected \(versions:.*2.*3.*\) \(preferred dialect: SMB 3\.1\.1\)/,
              ]
            },
          }
        )
      else
        test.merge(datastore: (test[:datastore] || {}).merge('SMB::ProtocolVersion' => '2,3'))
      end
    end
  )

  run_protocol_session_tests(tests, features: %w[smb_session_type])
end
