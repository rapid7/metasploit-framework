module Acceptance::Session
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
            # Not supported by Windows Meterpreter
            # MeterpreterTryToFork: false,
            MeterpreterDebugBuild: true
          }
        }
      }
    ],
    module_tests: [
      {
        name: "post/test/services",
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
        name: "post/test/cmd_exec",
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
        name: "post/test/extapi",
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
        name: "post/test/file",
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
        name: "post/test/get_env",
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
        name: "post/test/meterpreter",
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
        name: "post/test/railgun",
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
        name: "post/test/railgun_reverse_lookups",
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
        name: "post/test/registry",
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
        name: "post/test/search",
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
        name: "post/test/unix",
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
