module Acceptance::Session
  CMD = {
    payloads: [
      {
        name: 'windows/x64/shell_reverse_tcp',
        extension: '.exe',
        platforms: [:windows],
        execute_cmd: ['${payload_path}'],
        executable: true,
        generate_options: {
          '-f': 'exe'
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
            known_failures: []
          }
        }
      }
    ]
  }
end
