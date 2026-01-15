module Acceptance::Session
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
            known_failures: [
            ]
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
            known_failures: []
          }
        }
      },
      {
        name: "post/test/file",
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
        name: "post/test/socket_channels",
        platforms: [:linux, :osx, :windows],
        skipped: false,
        lines: {
          linux: {
            known_failures: [
              "[-] [[TCP-Server] Allows binding to port 0] FAILED: [TCP-Server] Allows binding to port 0",
              "[-] [[TCP-Server] Allows binding to port 0] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Accepts a connection] FAILED: [TCP-Server] Accepts a connection",
              "[-] [[TCP-Server] Accepts a connection] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Has the correct peer information] FAILED: [TCP-Server] Has the correct peer information",
              "[-] [[TCP-Server] Has the correct peer information] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Receives data from the peer] FAILED: [TCP-Server] Receives data from the peer",
              "[-] [[TCP-Server] Receives data from the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Sends data to the peer] FAILED: [TCP-Server] Sends data to the peer",
              "[-] [[TCP-Server] Sends data to the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events to the server] FAILED: [TCP-Server] Propagates close events to the server",
              "[-] [[TCP-Server] Propagates close events to the server] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events to the peer] FAILED: [TCP-Server] Propagates close events to the peer",
              "[-] [[TCP-Server] Propagates close events to the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events from the peer] FAILED: [TCP-Server] Propagates close events from the peer",
              "[-] [[TCP-Server] Propagates close events from the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] FAILED: [UDP] Has the correct peer information"
            ]
          },
          osx: {
              known_failures: [
              "[-] [[TCP-Server] Allows binding to port 0] FAILED: [TCP-Server] Allows binding to port 0",
              "[-] [[TCP-Server] Allows binding to port 0] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Accepts a connection] FAILED: [TCP-Server] Accepts a connection",
              "[-] [[TCP-Server] Accepts a connection] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Has the correct peer information] FAILED: [TCP-Server] Has the correct peer information",
              "[-] [[TCP-Server] Has the correct peer information] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Receives data from the peer] FAILED: [TCP-Server] Receives data from the peer",
              "[-] [[TCP-Server] Receives data from the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Sends data to the peer] FAILED: [TCP-Server] Sends data to the peer",
              "[-] [[TCP-Server] Sends data to the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events to the server] FAILED: [TCP-Server] Propagates close events to the server",
              "[-] [[TCP-Server] Propagates close events to the server] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events to the peer] FAILED: [TCP-Server] Propagates close events to the peer",
              "[-] [[TCP-Server] Propagates close events to the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events from the peer] FAILED: [TCP-Server] Propagates close events from the peer",
              "[-] [[TCP-Server] Propagates close events from the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] FAILED: [UDP] Has the correct peer information"
            ]
          },
          windows: {
            known_failures: [
              "[-] [[TCP-Server] Allows binding to port 0] FAILED: [TCP-Server] Allows binding to port 0",
              "[-] [[TCP-Server] Allows binding to port 0] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Accepts a connection] FAILED: [TCP-Server] Accepts a connection",
              "[-] [[TCP-Server] Accepts a connection] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Has the correct peer information] FAILED: [TCP-Server] Has the correct peer information",
              "[-] [[TCP-Server] Has the correct peer information] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Receives data from the peer] FAILED: [TCP-Server] Receives data from the peer",
              "[-] [[TCP-Server] Receives data from the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Sends data to the peer] FAILED: [TCP-Server] Sends data to the peer",
              "[-] [[TCP-Server] Sends data to the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events to the server] FAILED: [TCP-Server] Propagates close events to the server",
              "[-] [[TCP-Server] Propagates close events to the server] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events to the peer] FAILED: [TCP-Server] Propagates close events to the peer",
              "[-] [[TCP-Server] Propagates close events to the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] [[TCP-Server] Propagates close events from the peer] FAILED: [TCP-Server] Propagates close events from the peer",
              "[-] [[TCP-Server] Propagates close events from the peer] Exception: Rex::Post::Meterpreter::RequestError: core_channel_open: Operation failed: 1",
              "[-] FAILED: [UDP] Has the correct peer information",
              ["[-] FAILED: [UDP] Receives data from the peer", { flaky: true }],
            ]
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
