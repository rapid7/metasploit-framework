require_relative './shared'

module Acceptance::Session::Java
  MALLEABLE_C2_FIXTURE_PATH = File.expand_path('../../../../../spec/file_fixtures/malleable_c2', __FILE__)

  JAVA_METERPRETER = {
    payloads: [
      {
        name: "java/meterpreter_reverse_http",
        extension: ".jar",
        platforms: [:osx, :linux],
        execute_cmd: ["java", "-jar", "${payload_path}"],
        generate_options: {
          '-f': "jar"
        },
        datastore: {
          global: {},
          module: {
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
