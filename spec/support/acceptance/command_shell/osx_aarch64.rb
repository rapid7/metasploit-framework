# frozen_string_literal: true

module Acceptance::Session
  OSX_AARCH64 = {
    payloads: [
      {
        name: 'osx/aarch64/shell_reverse_tcp',
        extension: '',
        platforms: [:osx],
        executable: true,
        execute_cmd: ['${payload_path}'],
        generate_options: {
          '-f': 'macho'
        },
        datastore: {
          global: {},
          module: {}
        }
      }
    ],
    module_tests: [
      {
        name: 'post/test/services',
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
          linux:   { known_failures: [] },
          osx:     { known_failures: [] },
          windows: { known_failures: [] }
        }
      },
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
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ]
        ],
        skipped: false,
        lines: {
          linux:   { known_failures: [] },
          osx:     { known_failures: [] },
          windows: { known_failures: [] }
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
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ]
        ],
        skipped: false,
        lines: {
          linux:   { known_failures: [] },
          osx:     { known_failures: [] },
          windows: { known_failures: [] }
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
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ]
        ],
        skipped: false,
        lines: {
          linux:   { known_failures: [] },
          osx:     { known_failures: [] },
          windows: { known_failures: [] }
        }
      },
      {
        name: 'post/test/unix',
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: 'Payload not compiled for platform'
            }
          ],
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
          linux:   { known_failures: [] },
          osx:     { known_failures: [] },
          windows: { known_failures: [] }
        }
      }
    ]
  }
end
