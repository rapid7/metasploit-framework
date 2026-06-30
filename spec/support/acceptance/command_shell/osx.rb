# frozen_string_literal: true

module Acceptance::Session
  OSX = {
    payloads: [
      {
        name: 'osx/x64/shell_reverse_tcp',
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
          linux: { known_failures: [] },
          osx:   { known_failures: [] },
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
          linux: { known_failures: [] },
          osx:   { known_failures: [] },
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
          linux: { known_failures: [] },
          osx:   {
            known_failures: [
              # macOS command shell sessions don't expose TMP/TMPDIR environment variables,
              # so the post/test/file module cannot find a writable temp directory to work in.
              '[-] Post failed: RuntimeError Could not find tmp directory',
              ['[-] Call stack:', { flaky: true }],
              ["'Msf::ModuleTest::PostTestFileSystem#push_test_directory'", { flaky: true }],
              ["'Msf::Modules::Post__Test__File::MetasploitModule#setup'", { flaky: true }]
            ]
          },
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
          linux: { known_failures: [] },
          osx:   {
            known_failures: [
              # macOS command shell sessions do not have USER or environment variables
              # accessible via the shell_reverse_tcp payload's limited shell context.
              '[-] FAILED: should return user',
              '[-] FAILED: should handle $ sign',
              '[-] FAILED: should return multiple envs'
            ]
          },
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
          linux: { known_failures: [] },
          osx:   { known_failures: [] },
          windows: { known_failures: [] }
        }
      }
    ]
  }
end
