require 'acceptance_spec_helper'

def current_platform
  host_os = RbConfig::CONFIG['host_os']
  case host_os
  when /darwin/
    :osx
  when /mingw/
    :windows
  when /linux/
    :linux
  else
    raise "unknown host_os #{host_os.inspect}"
  end
end

# Allows restricting the tests of a specific Meterpreter's test suite with the METERPRETER environment variable
# @return [TrueClass, FalseClass] True if the given Meterpreter should be run, false otherwise.
def run_meterpreter?(meterpreter_config)
  name = meterpreter_config[:name].to_s
  ENV.fetch('METERPRETER', name).include?(name)
end

def supported_platform?(payload_config)
  payload_config[:platforms].include?(current_platform)
end

def human_name_for_payload(payload_config)
  is_stageless = payload_config[:name].include?('meterpreter_reverse_tcp')
  is_staged = payload_config[:name].include?('meterpreter/reverse_tcp')

  details = []
  details << 'stageless' if is_stageless
  details << 'staged' if is_staged
  details << payload_config[:name]

  details.join(' ')
end

def uncolorize(string)
  string.gsub(/\e\[\d+m/, '')
end

# @param [Object] hash A hash of key => hash
# @return [Object] Returns a new hash with the 'key' merged into hash value and all payloads
def with_meterpreter_name_merged(hash)
  hash.each_with_object({}) do |(name, config), acc|
    acc[name] = config.merge({ name: name })
  end
end

RSpec.describe 'Meterpreter', acceptance: true do
  include_context 'wait_for_expect'

  # Tests to ensure that Meterpreter is consistent across all implementations/operation systems
  METERPRETER_PAYLOADS = with_meterpreter_name_merged(
    {
      python: {
        module_tests: [
          {
            name: 'test/cmd_exec',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Passed: '
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: [
                  ['should return the stderr output', { flaky: true }],
                  ['should return the result of echo', { flaky: true }],
                  ['should return the result of echo with double quotes', { flaky: true }],
                  ['; Failed:', { flaky: true }],
                ]
              },
              linux: {
                required: [],
                acceptable_failures: [
                  ['should return the stderr output', { flaky: true }],
                  ['should return the result of echo', { flaky: true }],
                  ['should return the result of echo with double quotes', { flaky: true }],
                  ['; Failed:', { flaky: true }],
                ]
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/extapi',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                  'The "extapi" extension is not supported by this Meterpreter type',
                  'Call stack:',
                  'test/modules/post/test/extapi.rb'
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/file',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [

                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              linux: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              windows: {
                required: [

                ],
                acceptable_failures: [
                  # Python Meterpreter occasionally fails to verify that files exist
                  ['FAILED: should test for file existence', { flaky: true }],
                  'Post failed: Errno::ENOENT No such file or directory @ rb_sysopen - /bin/echo',
                  'Call stack:',
                  'test/modules/post/test/file.rb',
                  'test/lib/module_test.rb',
                ]
              }
            }
          },
          {
            name: 'test/get_env',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/meterpreter',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  '; Failed: '
                ],
                acceptable_failures: [
                  [
                    [
                      'FAILED: should return network interfaces',
                      'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                      'FAILED: should have an interface that matches session_host',
                      'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                      'stdapi_net_config_get_routes: Operation failed: Python exception: TypeError'
                    ],
                    { if: ENV['METERPRETER_RUNTIME_VERSION'] == '3.6' }
                  ],

                  # TODO: Python OSX Meterpreter chokes on netstat -rn output:
                  #   '172.16.83.3        0.c.29.a1.cb.67    UHLWIi     bridge1    358'
                  #  Exception:
                  #   'gateway': inet_pton(state, gateway),
                  #   *** error: illegal IP address string passed to inet_pton
                  [
                    [
                      'FAILED: should return network routes',
                      'stdapi_net_config_get_routes: Operation failed: Unknown error',
                    ],
                    { if: ENV['METERPRETER_RUNTIME_VERSION'] == '3.6' || !ENV['CI'] }
                  ],
                  [
                    [
                      'FAILED: should return network interfaces',
                      'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                      'FAILED: should have an interface that matches session_host',
                      'stdapi_net_config_get_interfaces: Operation failed: Python exception: TypeError',
                      'FAILED: should return network routes',
                      'stdapi_net_config_get_routes: Operation failed: Python exception: TypeError',
                    ],
                    { if: ENV['METERPRETER_RUNTIME_VERSION'] == '3.8' }
                  ]
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  # https://github.com/rapid7/metasploit-framework/pull/16178
                  [
                    [
                      'FAILED: should return the proper directory separator',
                      '; Failed: 1',
                    ],
                    { flaky: true }
                  ]
                ]
              }
            }
          },
          {
            name: 'test/railgun',
            platforms: [
              :windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              linux: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              },
              windows: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'stdapi_fs_file_expand_path: Operation failed: 1',
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              }
            }
          },
          {
            name: 'test/railgun_reverse_lookups',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  'Passed: 0; Failed: 2'
                ],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Passed: 0; Failed: 2'
                ]
              },
              linux: {
                required: [
                  'Passed: 0; Failed: 2'
                ],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Passed: 0; Failed: 2'
                ]
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/registry',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [
                  'Passed: 10; Failed: 1'
                ],
                acceptable_failures: [
                  'FAILED: should evaluate key existence',
                  'Passed: 10; Failed: 1'
                ]
              }
            }
          },
          {
            name: 'test/search',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/services',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [
                  'Passed: 11; Failed: 2'
                ],
                acceptable_failures: [
                  'FAILED: should start W32Time',
                  'FAILED: should stop W32Time',
                  'FAILED: should list services',
                  'Exception: RuntimeError : Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error',
                  'The "extapi" extension is not supported by this Meterpreter type',
                  'FAILED: should return info on a given service',
                  'FAILED: should create a service',
                  'FAILED: should return info on the newly-created service',
                  'FAILED: should delete the new service',
                  'FAILED: should return status on a given service',
                  'FAILED: should modify config on a given service',
                  'FAILED: should start a disabled service',
                  'FAILED: should restart a started service',
                  'Passed: 11; Failed: 2'
                ]
              }
            }
          },
          {
            name: 'test/unix',
            platforms: %i[osx linux],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
        ],
        payloads: [
          {
            name: 'python/meterpreter/reverse_tcp',
            extension: '.py',
            platforms: %i[osx linux windows],
            execute_cmd: ['python', '${payload_path}'],
            generate_options: {
              '-f': 'raw'
            },
            payload_options: {
              MeterpreterTryToFork: false,
              PythonMeterpreterDebug: true
            }
          },
        ]
      },
      php: {
        module_tests: [
          {
            name: 'test/cmd_exec',
            platforms: %i[
              osx
              linux
              windows
            ],
            lines: {
              all: {
                required: [

                ],
                acceptable_failures: []
              },
              osx: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              linux: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  'FAILED: should return the stderr output',
                  '; Failed: 1'
                ]
              }
            }
          },
          {
            name: 'test/extapi',
            platforms: %i[
              osx
              linux
              windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                  'The "extapi" extension is not supported by this Meterpreter type',
                  'Call stack:',
                  'test/modules/post/test/extapi.rb'
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/file',
            platforms: %i[
              osx
              linux
              windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: [
                  'FAILED: should read the binary data we just wrote',
                  '; Failed: 1'
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  'Post failed: Rex::Post::Meterpreter::RequestError stdapi_fs_chdir: Operation failed: 1',
                  'Call stack:',
                  'rex/post/meterpreter/extensions/stdapi/fs/dir.rb',
                  'msf/core/post/file.rb',
                  'test/modules/post/test/file.rb'
                ]
              }
            }
          },
          {
            name: 'test/get_env',
            platforms: %i[
              osx
              linux
              windows
            ],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/meterpreter',
            platforms: %i[
              osx
              linux
              windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                ],
                acceptable_failures: [
                  'FAILED: should return a list of processes',
                  'Failed: 1'
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/railgun',
            platforms: [
              :windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              },
              linux: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              },
              windows: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'stdapi_fs_file_expand_path: Operation failed: 1',
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              }
            }
          },
          {
            name: 'test/railgun_reverse_lookups',
            platforms: %i[
              osx
              linux
              windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Failed: 2'
                ]
              },
              linux: {
                required: [],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Failed: 2'
                ]
              },
              windows: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/registry',
            platforms: [
              :windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  'FAILED: should create keys',
                  'FAILED: should write REG_SZ values',
                  'FAILED: should write REG_DWORD values',
                  'FAILED: should delete keys',
                  'FAILED: should create unicode keys',
                  'FAILED: should write REG_SZ unicode values',
                  'FAILED: should delete unicode keys',
                  'FAILED: should evaluate key existence',
                  'PENDING: should evaluate value existence',
                  'FAILED: should read values',
                  'Exception: NoMethodError : undefined method',
                  'FAILED: should return normalized values',
                  'FAILED: should enumerate keys and values',
                  'Failed: 10'
                ]
              }
            }
          },
          {
            name: 'test/search',
            platforms: %i[
              osx
              linux
              windows
            ],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: [
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/services',
            platforms: [
              :windows
            ],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  'Exception: Rex::Post::Meterpreter::ExtensionLoadError : The "extapi" extension is not supported by this Meterpreter type',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented.',
                  'FAILED: should start W32Time',
                  'FAILED: should stop W32Time',
                  'FAILED: should list services',
                  'FAILED: should return info on a given service',
                  'FAILED: should create a service',
                  'FAILED: should return info on the newly-created service',
                  'FAILED: should delete the new service testes',
                  'FAILED: should return status on a given service',
                  'FAILED: should modify config on a given service',
                  'FAILED: should start a disabled service',
                  'FAILED: should restart a started service',
                  'FAILED: should raise a runtime exception if no access to service',
                  'FAILED: should raise a runtime exception if services doesnt exist'
                ]
              }
            }
          },
          {
            name: 'test/unix',
            platforms: %i[osx linux],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
        ],
        payloads: [
          {
            name: 'php/meterpreter_reverse_tcp',
            extension: '.php',
            platforms: %i[osx linux windows],
            execute_cmd: ['php', '${payload_path}'],
            generate_options: {
              '-f': 'raw'
            },
            payload_options: {
            }
          },
        ]
      },
      java: {
        module_tests: [
          {
            name: 'test/cmd_exec',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/extapi',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                  'The "extapi" extension is not supported by this Meterpreter type',
                  'Call stack:',
                  'test/modules/post/test/extapi.rb'
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/file',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [

                ],
                acceptable_failures: []
              },
              osx: {
                required: [
                  'Passed: '
                ],
                acceptable_failures: []
              },
              linux: {
                required: [
                  'Passed: '
                ],
                acceptable_failures: [
                  # Consistently fails on CI
                  ["Didn't read what we wrote, actual file on target: ||", { if: ENV['CI'] }],
                  # Occasionally fails
                  ['FAILED: should append binary data', { flaky: true }],
                  ['FAILED: should upload a file', { flaky: true }],
                  ['Failed:', { flaky: true }],
                  ['Exception: EOFError : EOFError', { flaky: true }]
                ]
              },
              windows: {
                required: [],
                acceptable_failures: [
                  ['FAILED: should upload a file', { flaky: true }],
                  ['Failed:', { flaky: true }],
                  ['Exception: EOFError : EOFError', { flaky: true }],
                  'Post failed: Errno::ENOENT No such file or directory @ rb_sysopen - /bin/echo',
                  'Call stack:',
                  'modules/post/test/file.rb',
                  'lib/module_test.rb'
                ]
              }
            }
          },
          {
            name: 'test/get_env',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/meterpreter',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/railgun',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              },
              linux: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              },
              windows: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                  'The command is not supported by this Meterpreter type',
                  'FAILED: Should retrieve the win32k file version',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented.',
                  'FAILED: Should include error information in the results',
                  'FAILED: Should support functions with no parameters',
                  'FAILED: Should support functions with literal parameters',
                  'FAILED: Should support functions with in/out/inout parameter types',
                  'FAILED: Should support calling multiple functions at once',
                  'FAILED: Should support writing memory',
                  'FAILED: Should support reading memory'
                ]
              }
            }
          },
          {
            name: 'test/railgun_reverse_lookups',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Failed: 2'
                ]
              },
              linux: {
                required: [],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Failed: 2'
                ]
              },
              windows: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/registry',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  'FAILED: should create keys',
                  'FAILED: should write REG_SZ values',
                  'FAILED: should write REG_DWORD values',
                  'FAILED: should delete keys',
                  'FAILED: should create unicode keys',
                  'FAILED: should write REG_SZ unicode values',
                  'FAILED: should delete unicode keys',
                  'FAILED: should evaluate key existence',
                  'PENDING: should evaluate value existence',
                  'FAILED: should read values',
                  'Exception: NoMethodError : undefined method',
                  'FAILED: should return normalized values',
                  'FAILED: should enumerate keys and values',
                  'Failed: 10'
                ]
              }
            }
          },
          {
            name: 'test/search',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: [
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/services',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  'stdapi_railgun_api: Operation failed: The command is not supported by this Meterpreter type',
                  'Exception: Rex::Post::Meterpreter::ExtensionLoadError : The "extapi" extension is not supported by this Meterpreter type',
                  'Exception: Rex::NotImplementedError : The requested method is not implemented.',
                  'FAILED: should start W32Time',
                  'FAILED: should stop W32Time',
                  'FAILED: should list services',
                  'FAILED: should return info on a given service',
                  'FAILED: should create a service',
                  'FAILED: should return info on the newly-created service',
                  'FAILED: should delete the new service testes',
                  'FAILED: should return status on a given service',
                  'FAILED: should modify config on a given service',
                  'FAILED: should start a disabled service',
                  'FAILED: should restart a started service',
                  'FAILED: should raise a runtime exception if no access to service',
                  'FAILED: should raise a runtime exception if services doesnt exist'
                ]
              }
            }
          },
          {
            name: 'test/unix',
            platforms: %i[osx linux],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
        ],
        payloads: [
          {
            name: 'java/meterpreter/reverse_tcp',
            extension: '.jar',
            platforms: %i[osx linux windows],
            execute_cmd: ['java', '-jar', '${payload_path}'],
            generate_options: {
              '-f': 'jar'
            },
            payload_options: {
              spawn: 0
            }
          }
        ]
      },
      mettle: {
        module_tests: [
          {
            name: 'test/cmd_exec',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                  'Passed: '
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: [
                  ['should return the stderr output', { flaky: true }],
                  ['; Failed:', { flaky: true }],
                ]
              },
              linux: {
                required: [],
                acceptable_failures: [
                  ['should return the stderr output', { flaky: true }],
                  ['; Failed:', { flaky: true }],
                ]
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/extapi',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [

                ]
              },
              osx: {
                required: [],
                acceptable_failures: [
                  'The "extapi" extension is not supported by this Meterpreter type',
                  'Call stack:',
                  'test/modules/post/test/extapi.rb'
                ]
              },
              linux: {
                required: [],
                acceptable_failures: [
                  'Post failed: RuntimeError x86_64-linux-musl/extapi not found',
                  'lib/metasploit_payloads/mettle.rb',
                  'lib/rex/post/meterpreter/client_core.rb',
                  'Call stack:',
                  'test/modules/post/test/extapi.rb'
                ]
              }
            }
          },
          {
            name: 'test/file',
            platforms: %i[osx linux],
            lines: {
              all: {
                required: [

                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              linux: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              }
            }
          },
          {
            name: 'test/get_env',
            platforms: %i[osx linux],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/meterpreter',
            platforms: %i[osx linux],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  '; Failed: 2'
                ],
                acceptable_failures:
                  [
                    'FAILED: should return network interfaces',
                    'FAILED: should have an interface that matches session_host',
                    '; Failed: 2'
                  ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/railgun',
            platforms: [
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              linux: {
                required: [
                ],
                acceptable_failures: [
                ]
              }
            }
          },
          {
            name: 'test/railgun_reverse_lookups',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  'Passed: 0; Failed: 2'
                ],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Passed: 0; Failed: 2'
                ]
              },
              linux: {
                required: [
                  'Passed: 0; Failed: 2'
                ],
                acceptable_failures: [
                  'FAILED: should return a constant name given a const and a filter',
                  'FAILED: should return an error string given an error code',
                  'Passed: 0; Failed: 2'
                ]
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/registry',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [
                  'Passed: 10; Failed: 1'
                ],
                acceptable_failures: [
                ]
              }
            }
          },
          {
            name: 'test/search',
            platforms: [
              # TODO: Hangs:
              #  :osx,
              :linux,
              :windows
            ],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/services',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [
                  'Passed: 11; Failed: 2'
                ],
                acceptable_failures: [
                  'FAILED: should start W32Time',
                  'FAILED: should stop W32Time',
                  'FAILED: should list services',
                  'Exception: RuntimeError : Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error',
                  'The "extapi" extension is not supported by this Meterpreter type',
                  'FAILED: should return info on a given service',
                  'FAILED: should create a service',
                  'FAILED: should return info on the newly-created service',
                  'FAILED: should delete the new service',
                  'FAILED: should return status on a given service',
                  'FAILED: should modify config on a given service',
                  'FAILED: should start a disabled service',
                  'FAILED: should restart a started service',
                  'Passed: 11; Failed: 2'
                ]
              }
            }
          },
          {
            name: 'test/unix',
            platforms: %i[osx linux],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
        ],
        payloads: [
          {
            name: 'linux/x64/meterpreter/reverse_tcp',
            extension: '',
            platforms: [:linux],
            executable: true,
            execute_cmd: ['${payload_path}'],
            generate_options: {
              '-f': 'elf'
            },
            payload_options: {
              MeterpreterTryToFork: false
            }
          },
          {
            name: 'osx/x64/meterpreter_reverse_tcp',
            extension: '',
            platforms: [:osx],
            executable: true,
            execute_cmd: ['${payload_path}'],
            generate_options: {
              '-f': 'macho'
            },
            payload_options: {
              MeterpreterTryToFork: false
            }
          },
          # {
          #   name: 'osx/x64/meterpreter/reverse_tcp',
          #   extension: '',
          #   platforms: [:osx],
          #   executable: true,
          #   execute_cmd: ['${payload_path}'],
          #   generate_options: {
          #     '-f': 'macho'
          #   },
          #   payload_options: {
          #     MeterpreterTryToFork: false
          #   }
          # }
        ]
      },
      windows_meterpreter: {
        module_tests: [
          {
            name: 'test/cmd_exec',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/extapi',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/file',
            platforms: [:windows],
            lines: {
              all: {
                required: [

                ],
                acceptable_failures: [
                  'Post failed: Errno::ENOENT No such file or directory @ rb_sysopen - /bin/echo',
                  'Call stack:',
                  'test/modules/post/test/file.rb',
                  'test/lib/module_test.rb',
                ]
              },
              windows: {
                required: [],
                acceptable_failures: [
                ]
              }
            }
          },
          {
            name: 'test/get_env',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/meterpreter',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/railgun',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              windows: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: [
                ]
              }
            }
          },
          {
            name: 'test/railgun_reverse_lookups',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              windows: {
                required: [
                  'Failed: 0'
                ],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/registry',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                ]
              }
            }
          },
          {
            name: 'test/search',
            platforms: %i[osx linux windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: [
                ]
              },
              osx: {
                required: [],
                acceptable_failures: [
                ]
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: []
              }
            }
          },
          {
            name: 'test/services',
            platforms: [:windows],
            lines: {
              all: {
                required: [
                ],
                acceptable_failures: []
              },
              osx: {
                required: [],
                acceptable_failures: []
              },
              linux: {
                required: [],
                acceptable_failures: []
              },
              windows: {
                required: [],
                acceptable_failures: [
                  'FAILED: should start W32Time',
                  ['Exception: TypeError : exception class/object expected', { flaky: true }],
                  'FAILED: should stop W32Time',
                  'FAILED: should list services',
                  'Exception: RuntimeError : Unable to open service manager: FormatMessage failed to retrieve the error',
                  'Exception: RuntimeError : Could not open service. OpenServiceA error: FormatMessage failed to retrieve the error',
                  'Request Error extapi_service_query: Operation failed: 1060 falling back to registry technique',
                  'The "extapi" extension is not supported by this Meterpreter type',
                  'FAILED: should return info on a given service',
                  'FAILED: should create a service',
                  'FAILED: should return info on the newly-created service',
                  'FAILED: should delete the new service',
                  'FAILED: should return status on a given service',
                  'FAILED: should modify config on a given service',
                  'FAILED: should start a disabled service',
                  'FAILED: should restart a started service'
                ]
              }
            }
          },
        ],
        payloads: [
          {
            name: 'windows/meterpreter/reverse_tcp',
            extension: '.exe',
            platforms: [:windows],
            execute_cmd: ['${payload_path}'],
            executable: true,
            generate_options: {
              '-f': 'exe'
            },
            payload_options: {
              MeterpreterTryToFork: false
            }
          },
        ]
      }
    }
  )

  let_it_be(:port_generator) { Acceptance::PortGenerator.new }

  # Driver instance, keeps track of all open processes/payloads/etc, so they can be closed cleanly
  let_it_be(:driver) do
    driver = Acceptance::ConsoleDriver.new
    driver
  end

  # Opens a test console with the test loadpath specified
  let_it_be(:console) do
    console = driver.open_console

    # Load the test modules
    console.sendline('loadpath test/modules')
    console.recvuntil(/Loaded \d+ modules:[^\n]*\n/)
    console.recvuntil(/\d+ auxiliary modules[^\n]*\n/)
    console.recvuntil(/\d+ exploit modules[^\n]*\n/)
    console.recvuntil(/\d+ post modules[^\n]*\n/)
    console.recvuntil(Acceptance::Console.prompt)

    # Read the remaining console
    # console.sendline "quit -y"
    # console.recvall

    console
  end

  METERPRETER_PAYLOADS.each do |meterpreter_name, meterpreter_config|
    describe "#{meterpreter_name}#{ENV.fetch('METERPRETER_RUNTIME_VERSION', '')}", focus: meterpreter_config[:focus] do
      meterpreter_config[:payloads].each do |payload_config|
        describe human_name_for_payload(payload_config).to_s, if: run_meterpreter?(meterpreter_config) && supported_platform?(payload_config) do
          let(:payload) { Acceptance::Payload.new(payload_config) }

          # The shared payload session instance that will be reused across the test run
          let(:await_session_id) do
            payload_config[:payload_options].merge!({ lport: port_generator.next, lhost: '127.0.0.1' })

            console.sendline "use #{payload.name}"
            console.recvuntil(Acceptance::Console.prompt)

            # Generate the payload
            console.sendline payload.generate_command
            console.recvuntil(/Writing \d+ bytes[^\n]*\n/)
            generate_result = console.recvuntil(Acceptance::Console.prompt)

            expect(generate_result.lines).to_not include(match('generation failed'))
            wait_for_expect do
              expect(payload.size).to be > 0
            end

            console.sendline 'to_handler'
            console.recvuntil(/Started reverse TCP handler[^\n]*\n/)
            driver.run_payload(payload)

            session_opened_matcher = /Meterpreter session (\d+) opened[^\n]*\n/
            session_message = console.recvuntil(session_opened_matcher)
            session_id = session_message[session_opened_matcher, 1]
            expect(session_id).to_not be_nil

            session_id
          end

          before :each do
            driver.close_payloads
            console.reset
            await_session_id
          end

          after :all do
            driver.close_payloads
            console.reset
          end

          meterpreter_config[:module_tests].each do |module_test|
            describe module_test[:name].to_s do
              it "successfully opens a session for the #{payload_config[:name].inspect} payload and passes the #{module_test[:name].inspect} tests", if: run_meterpreter?(meterpreter_config) && supported_platform?(payload_config) && supported_platform?(module_test) do
                console.sendline("use #{module_test[:name]}")
                console.recvuntil(Acceptance::Console.prompt)

                console.sendline("run session=#{await_session_id} AddEntropy=true Verbose=true")

                # Expect happiness
                test_result = console.recvuntil('Post module execution completed')

                # Ensure there are no failures, and assert tests are complete
                aggregate_failures do
                  acceptable_failures = module_test.dig(:lines, :all, :acceptable_failures) || []
                  acceptable_failures += module_test.dig(:lines, current_platform, :acceptable_failures) || []
                  acceptable_failures = acceptable_failures.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

                  required_lines = module_test.dig(:lines, :all, :required) || []
                  required_lines += module_test.dig(:lines, current_platform, :required) || []
                  required_lines = required_lines.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

                  # Skip any ignored lines from the validation input
                  validated_lines = test_result.lines.reject do |line|
                    is_acceptable = acceptable_failures.any? do |acceptable_failure|
                      line.match?(acceptable_failure.value) &&
                        acceptable_failure.if?
                    end

                    is_acceptable
                  end

                  validated_lines.each do |test_line|
                    test_line = uncolorize(test_line)
                    expect(test_line).to_not include('FAILED', '[-] FAILED', '[-] Exception', '[-] '), "Unexpected error: #{test_line}"
                  end

                  # Assert all expected lines are present, unless they're flaky
                  required_lines.each do |required|
                    next unless required.if?

                    expect(test_result).to include(required.value)
                  end

                  # Assert all ignored lines are present, if they are not present - they should be removed from
                  # the calling config
                  acceptable_failures.each do |acceptable_failure|
                    next if acceptable_failure.flaky?
                    next unless acceptable_failure.if?

                    expect(test_result).to include(acceptable_failure.value)
                  end
                end
              ensure
                Allure.add_attachment(
                  name: 'payload',
                  source: payload.as_readable_text,
                  type: Allure::ContentType::TXT,
                  test_case: false
                )

                Allure.add_attachment(
                  name: 'console data',
                  source: console.all_data,
                  type: Allure::ContentType::TXT,
                  test_case: false
                )
              end
            end
          end
        end
      end
    end
  end
end
