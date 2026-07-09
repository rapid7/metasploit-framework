require_relative './shared'

module Acceptance::Session::WindowsMeterpreter
  WINDOWS_METERPRETER = {
    payloads: [
      {
        name: "windows/x64/meterpreter/reverse_tcp",
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
            # Not supported by Windows Meterpreter
            # MeterpreterTryToFork: false,
            MeterpreterDebugBuild: false
          }
        }
      }
    ],
    module_tests: [
      {
        name: "post/test/socket_channels",
        platforms: [:linux, :osx, :windows],
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
