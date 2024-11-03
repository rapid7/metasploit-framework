module Acceptance::Session
  POWERSHELL = {
    payloads: [
      {
        name: 'cmd/windows/powershell_reverse_tcp',
        extension: '.ps1',
        platforms: [:windows],
        execute_cmd: ['powershell ${payload_path}'],
        executable: true,
        generate_options: {
          '-f': 'raw'
        },
        datastore: {
          global: {},
          module: {}
        }
      }
    ],
    module_tests: [
      {
        name: 'post/test/cmd_exec',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: 'post/test/file',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: 'post/test/get_env',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: 'post/test/registry',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Windows only test'
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: 'Windows only test'
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] FAILED: should write REG_SZ unicode values"
            ]
          }
        }
      }
    ]
  }
end
