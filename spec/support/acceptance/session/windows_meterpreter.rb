require_relative './shared'

module Acceptance::Session::WindowsMeterpreter
  MALLEABLE_C2_FIXTURE_PATH = File.expand_path('../../../../../spec/file_fixtures/malleable_c2', __FILE__)

  WINDOWS_METERPRETER = {
    payloads: [
      {
        name: "windows/meterpreter_reverse_http",
        extension: ".exe",
        platforms: [:windows],
        execute_cmd: ["${payload_path}"],
        executable: true,
        generate_options: {
          '-f': "exe"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterDebugBuild: true,
            MALLEABLEC2: File.join(MALLEABLE_C2_FIXTURE_PATH, 'minimal_uris_headers.profile')
          }
        }
      },
      {
        name: "windows/x64/meterpreter_reverse_http",
        extension: ".exe",
        platforms: [:windows],
        execute_cmd: ["${payload_path}"],
        executable: true,
        generate_options: {
          '-f': "exe"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterDebugBuild: false,
            MALLEABLEC2: File.join(MALLEABLE_C2_FIXTURE_PATH, 'minimal_uris_headers.profile')
          }
        }
      }
    ],
    module_tests: [
      {
        name: "post/test/socket_channels",
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: "Payload not compiled for platform"
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: "Payload not compiled for platform"
            }
          ],
          :windows
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: [
              *Acceptance::Session::Shared::SOCKET_CHANNEL_FLAKES
            ]
          },
          osx: {
            known_failures: [
              *Acceptance::Session::Shared::SOCKET_CHANNEL_FLAKES
            ]
          },
          windows: {
            known_failures: [
              *Acceptance::Session::Shared::SOCKET_CHANNEL_FLAKES
            ]
          }
        }
      }
    ]
  }
end
