require_relative './shared'

module Acceptance::Session::Python
  MALLEABLE_C2_FIXTURE_PATH = File.expand_path('../../../../../spec/file_fixtures/malleable_c2', __FILE__)

  PYTHON_METERPRETER = {
    payloads: [
      {
        name: "python/meterpreter_reverse_http",
        extension: ".py",
        platforms: [:osx, :linux, :windows],
        execute_cmd: ["python", "${payload_path}"],
        generate_options: {
          '-f': "raw"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterTryToFork: false,
            PythonMeterpreterDebug: true,
            MALLEABLEC2: File.join(MALLEABLE_C2_FIXTURE_PATH, 'minimal_uris_headers.profile')
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
