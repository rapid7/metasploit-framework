require_relative './shared'

module Acceptance::Session::Php
  MALLEABLE_C2_FIXTURE_PATH = File.expand_path('../../../../../spec/file_fixtures/malleable_c2', __FILE__)

  PHP_METERPRETER = {
    payloads: [
      {
        name: "php/meterpreter_reverse_http",
        extension: ".php",
        platforms: [:osx, :linux, :windows],
        execute_cmd: ["php", "${payload_path}"],
        generate_options: {
          '-f': "raw"
        },
        datastore: {
          global: {},
          module: {
            MeterpreterDebugBuild: true,
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
              ["[-] [[UDP] Has the correct peer information] FAILED: [UDP] Has the correct peer information", { if: [:session_runtime_version, :==, "meterpreter/php5.3"] }],
              ["[-] [[UDP] Has the correct peer information] Exception: Errno::ENOTSOCK", { if: [:session_runtime_version, :==, "meterpreter/php5.3"] }],
              ["[-] [[UDP] Receives data from the peer] FAILED: [UDP] Receives data from the peer", { if: [:session_runtime_version, :==, "meterpreter/php5.3"] }],
              ["[-] [[UDP] Receives data from the peer] Exception: Errno::ENOTSOCK", { if: [:session_runtime_version, :==, "meterpreter/php5.3"] }],
              *Acceptance::Session::Shared::SOCKET_CHANNEL_FLAKES
            ]
          }
        }
      }
    ]
  }
end
