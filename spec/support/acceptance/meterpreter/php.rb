require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  PHP_METERPRETER = {
    payloads: [
      {
        name: "php/meterpreter_reverse_tcp",
        extension: ".php",
        platforms: [:osx, :linux, :windows],
        execute_cmd: ["php", "${payload_path}"],
        generate_options: {
          '-f': "raw"
        },
        datastore: {
          global: {},
          module: {
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
          [
            :windows,
            {
              skip: [
                :meterpreter_runtime_version,
                :==,
                "php5.3"
              ],
              reason: "Skip PHP 5.3 as the tests timeout - due to cmd_exec taking 15 seconds for each call. Caused by failure to detect feof correctly - https://github.com/rapid7/metasploit-payloads/blame/c7f7bc2fc0b86e17c3bc078149c71745c5e478b3/php/meterpreter/meterpreter.php#L1127-L1145"
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
      },
      {
        name: "test/cmd_exec",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] FAILED: should return the stderr output"
            ]
          }
        }
      },
      {
        name: "test/extapi",
        platforms: [:linux, :osx, :windows],
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
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: [
              "[-] FAILED: should read the binary data we just wrote"
            ]
          },
          osx: {
            known_failures: [
              "[-] FAILED: should read the binary data we just wrote"
            ]
          },
          windows: {
            known_failures: [
              "[-] [should delete a symbolic link target] FAILED: should delete a symbolic link target",
              "[-] [should delete a symbolic link target] Exception: Rex::Post::Meterpreter::RequestError: stdapi_fs_delete_dir: Operation failed: 1",
              "[-] FAILED: should read the binary data we just wrote"
            ]
          }
        }
      },
      {
        name: "test/get_env",
        platforms: [:linux, :osx, :windows],
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
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: [
              "[-] FAILED: should return a list of processes"
            ]
          },
          windows: {
            known_failures: []
          }
        }
      },
      {
        name: "test/railgun",
        platforms: [:linux, :osx, :windows],
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
        platforms: [:linux, :osx, :windows],
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
          [
            :windows,
            {
              skip: [
                :meterpreter_runtime_version,
                :==,
                "php5.3"
              ],
              reason: "Skip PHP 5.3 as the tests timeout - due to cmd_exec taking 15 seconds for each call. Caused by failure to detect feof correctly - https://github.com/rapid7/metasploit-payloads/blame/c7f7bc2fc0b86e17c3bc078149c71745c5e478b3/php/meterpreter/meterpreter.php#L1127-L1145"
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
      },
      {
        name: "test/search",
        platforms: [:linux, :osx, :windows],
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
