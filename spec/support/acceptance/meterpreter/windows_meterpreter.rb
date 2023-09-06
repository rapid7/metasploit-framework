require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  WINDOWS_METERPRETER = {
    payloads: [
      {
        name: "windows/meterpreter/reverse_tcp",
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
            # Not suported by Windows Meterpreter
            # MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true
          }
        }
      }
    ],
    module_tests: [
      {
        name: "test/services",
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: "Windows only test"
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: "Windows only test"
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
        name: "test/cmd_exec",
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
        name: "test/extapi",
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
        name: "test/file",
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
        name: "test/get_env",
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
        name: "test/meterpreter",
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
        name: "test/railgun",
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
        name: "test/railgun_reverse_lookups",
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
        name: "test/registry",
        platforms: [
          [
            :linux,
            {
              skip: true,
              reason: "Windows only test"
            }
          ],
          [
            :osx,
            {
              skip: true,
              reason: "Windows only test"
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
        name: "test/search",
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
        name: "test/unix",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Unix only test"
            }
          ]
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
