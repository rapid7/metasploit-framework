require 'support/acceptance/meterpreter'

module Acceptance::Meterpreter
  JAVA_METERPRETER = {
    payloads: [
      {
        name: "java/meterpreter/reverse_tcp",
        extension: ".jar",
        platforms: [:osx, :linux, :windows],
        execute_cmd: ["java", "-jar", "${payload_path}"],
        generate_options: {
          '-f': "jar"
        },
        datastore: {
          global: {},
          module: {
            spawn: 0
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
            known_failures: [
              "[-] [should start W32Time] FAILED: should start W32Time",
              "[-] [should start W32Time] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should stop W32Time] FAILED: should stop W32Time",
              "[-] [should stop W32Time] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should create a service testes] FAILED: should create a service testes",
              "[-] [should create a service testes] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should return info on the newly-created service testes] Could not retrieve the start type of the testes service!",
              "[-] FAILED: should return info on the newly-created service testes",
              "[-] [should delete the new service testes] FAILED: should delete the new service testes",
              "[-] [should delete the new service testes] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should return status on a given service winmgmt] FAILED: should return status on a given service winmgmt",
              "[-] [should return status on a given service winmgmt] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should modify config on a given service] FAILED: should modify config on a given service",
              "[-] [should modify config on a given service] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should start a disabled service] FAILED: should start a disabled service",
              "[-] [should start a disabled service] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should restart a started service W32Time] FAILED: should restart a started service W32Time",
              "[-] [should restart a started service W32Time] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should raise a runtime exception if no access to service] FAILED: should raise a runtime exception if no access to service",
              "[-] [should raise a runtime exception if no access to service] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)",
              "[-] [should raise a runtime exception if services doesnt exist] FAILED: should raise a runtime exception if services doesnt exist",
              "[-] [should raise a runtime exception if services doesnt exist] Exception: Rex::Post::Meterpreter::RequestError: stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type (java/windows)"
            ]
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
            known_failures: []
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
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: [
              "[-] [should delete a symbolic link target] failed to create the symbolic link"
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
            known_failures: []
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
            known_failures: [
              "[-] FAILED: should write REG_EXPAND_SZ values",
              "[-] FAILED: should write REG_SZ unicode values"
            ]
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
