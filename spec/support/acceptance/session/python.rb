module Acceptance::Session
  PYTHON_METERPRETER = {
    payloads: [
      {
        name: "python/meterpreter_reverse_tcp",
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
            PythonMeterpreterDebug: true
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
            known_failures: [
              "[-] [should start W32Time] FAILED: should start W32Time",
              "[-] [should start W32Time] Exception: RuntimeError: Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error for value 0x6.",
              "[-] [should stop W32Time] FAILED: should stop W32Time",
              "[-] [should stop W32Time] Exception: RuntimeError: Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error for value 0x6.",
              "[-] [should list services] FAILED: should list services",
              # Ruby 3.2
              ["[-] [should list services] Exception: NoMethodError: undefined method `service' for nil:NilClass", { flaky: true }],
              # Ruby 3.4 - https://www.ruby-lang.org/en/news/2024/12/25/ruby-3-4-0-released/#Compatibility%20issues
              ["[-] [should list services] Exception: NoMethodError: undefined method 'service' for nil", { flaky: true }],
              "[-] [should return info on a given service winmgmt] FAILED: should return info on a given service winmgmt",
              # Ruby 3.2
              ["[-] [should return info on a given service winmgmt] Exception: NoMethodError: undefined method `service' for nil:NilClass", { flaky: true }],
              # Ruby 3.4 - https://www.ruby-lang.org/en/news/2024/12/25/ruby-3-4-0-released/#Compatibility%20issues
              ["[-] [should return info on a given service winmgmt] Exception: NoMethodError: undefined method 'service' for nil", { flaky: true }],
              "[-] FAILED: should create a service testes",
              "[-] [should return info on the newly-created service testes] FAILED: should return info on the newly-created service testes",
              # Ruby 3.2
              ["[-] [should return info on the newly-created service testes] Exception: NoMethodError: undefined method `service' for nil:NilClass", { flaky: true }],
              # Ruby 3.4 - https://www.ruby-lang.org/en/news/2024/12/25/ruby-3-4-0-released/#Compatibility%20issues
              ["[-] [should return info on the newly-created service testes] Exception: NoMethodError: undefined method 'service' for nil", { flaky: true }],
              "[-] [should delete the new service testes] FAILED: should delete the new service testes",
              "[-] [should delete the new service testes] Exception: RuntimeError: Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error for value 0x6.",
              "[-] [should return status on a given service winmgmt] FAILED: should return status on a given service winmgmt",
              "[-] [should return status on a given service winmgmt] Exception: RuntimeError: Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error for value 0x6.",
              "[-] [should modify config on a given service] FAILED: should modify config on a given service",
              "[-] [should modify config on a given service] Exception: RuntimeError: Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error for value 0x6.",
              "[-] FAILED: should start a disabled service",
              "[-] [should restart a started service W32Time] FAILED: should restart a started service W32Time",
              "[-] [should restart a started service W32Time] Exception: RuntimeError: Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error for value 0x6."
            ]
          }
        }
      },
      {
        name: "post/test/cmd_exec",
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
        name: "post/test/extapi",
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
              # Ruby 3.2
              ["[-] [should return clipboard jpg dimensions] FAILED: should return clipboard jpg dimensions", { flaky: true }],
              ["[-] [should return clipboard jpg dimensions] Exception: NoMethodError: undefined method `clipboard' for nil:NilClass", { flaky: true }],
              ["[-] [should download clipboard jpg data] FAILED: should download clipboard jpg data", { flaky: true }],
              ["[-] [should download clipboard jpg data] Exception: NoMethodError: undefined method `clipboard' for nil:NilClass", { flaky: true }],
              # Ruby 3.4 - https://www.ruby-lang.org/en/news/2024/12/25/ruby-3-4-0-released/#Compatibility%20issues
              ["[-] [should return clipboard jpg dimensions] FAILED: should return clipboard jpg dimensions", { flaky: true }],
              ["[-] [should return clipboard jpg dimensions] Exception: NoMethodError: undefined method 'clipboard' for nil", { flaky: true }],
              ["[-] [should download clipboard jpg data] FAILED: should download clipboard jpg data", { flaky: true }],
              ["[-] [should download clipboard jpg data] Exception: NoMethodError: undefined method 'clipboard' for nil", { flaky: true }],
            ]
          }
        }
      },
      {
        name: "post/test/file",
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
        name: "post/test/get_env",
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
        name: "post/test/meterpreter",
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
            ]
          }
        }
      },
      {
        name: "post/test/railgun",
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
        name: "post/test/railgun_reverse_lookups",
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
