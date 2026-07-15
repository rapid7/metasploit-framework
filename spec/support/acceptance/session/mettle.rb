require_relative './shared'

module Acceptance::Session::Mettle
  MALLEABLE_C2_FIXTURE_PATH = File.expand_path('../../../../../spec/file_fixtures/malleable_c2', __FILE__)

  METTLE_METERPRETER = {
    payloads: [
      {
        name: "linux/x64/meterpreter_reverse_http",
        extension: "",
        platforms: [:linux],
        executable: true,
        execute_cmd: ["${payload_path}"],
        generate_options: {
          '-f': "elf"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true,
            MALLEABLEC2: File.join(MALLEABLE_C2_FIXTURE_PATH, 'minimal_uris_headers.profile')
          }
        }
      },
      {
        name: "osx/x64/meterpreter_reverse_http",
        extension: "",
        platforms: [:osx],
        executable: true,
        execute_cmd: ["${payload_path}"],
        generate_options: {
          '-f': "macho"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true,
            MALLEABLEC2: File.join(MALLEABLE_C2_FIXTURE_PATH, 'minimal_uris_headers.profile')
          }
        }
      }
    ],
    module_tests: [
      {
        name: "post/test/socket_channels",
        platforms: [:linux, :osx],
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
