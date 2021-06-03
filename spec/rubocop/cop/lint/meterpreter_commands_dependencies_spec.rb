require 'spec_helper'
require 'rubocop/cop/lint/meterpreter_commands_dependencies'

RSpec.describe RuboCop::Cop::Lint::MeterpreterCommandDependencies, :config do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  it 'accepts a valid command list' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if no compat node is present and no method calls that it will not generate anything/alter the file' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
          )
        end
        def run
        end
      end
    RUBY
  end

  it 'verifies that meterpreter method calls are matched and added to the commands array' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that is the command list has a command present but no corresponding call, the command should be removed' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                  stdapi_fs_delete_file
                  ^^^^^^^^^^^^^^^^^^^^^ Compatibility command does not have an associated method call.
                ]
              }
            }
          )
          register_options([])
        end
        def run
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ]
              }
            }
          )
          register_options([])
        end
        def run
        end
      end
    RUBY
  end

  it 'generates a list of meterpreter command dependencies based off meterpreter api calls in modules that currently have an empty commands array' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_delete_file
                ]
              }
            }
          )
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'removes a redundant command from the list of meterpreter command dependencies based off meterpreter api calls in modules that currently have a command that is no longer required' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Compatibility command does not have an associated method call.
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that the commands arrays contents are unique as well as being sorted alphabetically' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_fs_delete_file
                    ^^^^^^^^^^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_delete_file
                    ^^^^^^^^^^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          session.fs.file.ls("some_file")
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                    stdapi_fs_ls
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          session.fs.file.ls("some_file")
        end
      end
    RUBY
  end

  it 'ensures there are not duplicate entries in the commands list' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                  ]
                }
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_ls
                  ]
                }
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
        end
      end
    RUBY
  end

  it 'handles when there are two or more identical method calls ' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a commands array is not present within a module it will be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a meterpreter hash and a commands array is present within the module, if not it should be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
              ^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a compat hash, meterpreter hash and a commands array is present within the module, if not it should be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5'
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if `update_info(` is missing that the method calls are matched and added to the commands array ' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_delete_file
                ]
              }
            }
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if `update_info(` is missing but initialize has `(info={})` that the method calls are matched and added to the commands array ' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info={})
          super
          ^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info={})
          super
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_delete_file
                ]
              }
            }
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if there are two classes, that it will successfully iterate over them and match the method calls in the appropriate class and generate a commands list' do
    expect_offense(<<~RUBY)
      class DummyModule
        class HelperClass
          def initialize
            @foo = 123
          end
        end

        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
        end

        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        class HelperClass
          def initialize
            @foo = 123
          end
        end

        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_delete_file
                ]
              }
            }
          )
        end

        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verfies that the cop will also work with modules' do
    expect_offense(<<~RUBY)
      module Msf::Post::Process
             ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        def meterpreter_get_processes
          begin
            return session.sys.process.get_processes.map { |p| p.slice('name', 'pid') }
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          rescue Rex::Post::Meterpreter::RequestError
            shell_get_processes
          end
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      module Msf::Post::Process
        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_sys_process_get_processes
                  ]
                }
              }
            )
          )
        end

        def meterpreter_get_processes
          begin
            return session.sys.process.get_processes.map { |p| p.slice('name', 'pid') }
          rescue Rex::Post::Meterpreter::RequestError
            shell_get_processes
          end
        end
      end
    RUBY
  end

  it 'handles two classes being in the same file' do
    expect_offense(<<~RUBY)
      class DummyModuleOne
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
              ^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end

      class DummyModuleTwo
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
              ^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModuleOne
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end

      class DummyModuleTwo
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_ls
                  ]
                }
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a there is no initialise method, that it should be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
            ^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_delete_file
                  ]
                }
              }
            )
          )
        end

        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verfies that if compat has another value, that the meterpreter hash will be appended onto it, not replace it' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Payload'        => {
                'Compat'       =>
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                {
                  'PayloadType' => 'cmd'
                }
              }
            )
          )
        end

        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Payload'        => {
                'Compat'       =>
                {
                  'PayloadType' => 'cmd'
                  'Meterpreter' => {
                    'Commands' => %w[
                      stdapi_fs_delete_file
                    ]
                  }
                }
              }
            )
          )
        end

        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'successfully corrects helper methods too' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
        end

        def run
          some_helper_method(session)         
        end

        def some_helper_method(session)
         session.fs.file.rm("some_file")
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_delete_file
                ]
              }
            }
          )
        end

        def run
          some_helper_method(session)         
        end

        def some_helper_method(session)
         session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if NTDS parser object is called that it adds the correct command name' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
        end

        def run
          ntds_parser = Metasploit::Framework::NTDS::Parser.new(client, ntds_file)
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          client.extapi.ntds.parse("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  extapi_ntds_parse
                ]
              }
            }
          )
        end

        def run
          ntds_parser = Metasploit::Framework::NTDS::Parser.new(client, ntds_file)
          client.extapi.ntds.parse("some_file")
        end
      end
    RUBY
  end

  it 'handles `abrt_raceabrt_priv_esc.rb` edge cases that were not being matched for unknown reasons' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
            super(update_info(info,
              'Name'           => 'ABRT raceabrt Privilege Escalation',
              'Description'    => %q{
                This module attempts to gain root privileges on Linux systems with
                a vulnerable version of Automatic Bug Reporting Tool (ABRT) configured
                as the crash handler.
        
                A race condition allows local users to change ownership of arbitrary
                files (CVE-2015-3315). This module uses a symlink attack on
                `/var/tmp/abrt/*/maps` to change the ownership of `/etc/passwd`,
                then adds a new user with UID=0 GID=0 to gain root privileges.
                Winning the race could take a few minutes.
        
                This module has been tested successfully on:
        
                abrt 2.1.11-12.el7 on RHEL 7.0 x86_64;
                abrt 2.1.5-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.1-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.2-2.fc20 on Fedora Desktop 20 x86_64;
                abrt 2.3.0-3.fc21 on Fedora Desktop 21 x86_64.
              },
              'License'        => MSF_LICENSE,
              'Author'         =>
                [
                  'Tavis Ormandy', # Discovery and C exploit
                  'bcoles' # Metasploit
                ],
              'DisclosureDate' => '2015-04-14',
              'Platform'       => [ 'linux' ],
              'Arch'           => [ ARCH_X86, ARCH_X64 ],
              'SessionTypes'   => [ 'shell', 'meterpreter' ],
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_sys_process_*
                    ^^^^^^^^^^^^^^^^^^^^ Compatibility command does not have an associated method call.
                  ]
                }
              }
            )
          )
        end
        def run
          session.sys.process.execute 'shell', "command"
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          passwd_stat = session.fs.file.stat(@chown_file).stathash
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
            super(update_info(info,
              'Name'           => 'ABRT raceabrt Privilege Escalation',
              'Description'    => %q{
                This module attempts to gain root privileges on Linux systems with
                a vulnerable version of Automatic Bug Reporting Tool (ABRT) configured
                as the crash handler.
        
                A race condition allows local users to change ownership of arbitrary
                files (CVE-2015-3315). This module uses a symlink attack on
                `/var/tmp/abrt/*/maps` to change the ownership of `/etc/passwd`,
                then adds a new user with UID=0 GID=0 to gain root privileges.
                Winning the race could take a few minutes.
        
                This module has been tested successfully on:
        
                abrt 2.1.11-12.el7 on RHEL 7.0 x86_64;
                abrt 2.1.5-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.1-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.2-2.fc20 on Fedora Desktop 20 x86_64;
                abrt 2.3.0-3.fc21 on Fedora Desktop 21 x86_64.
              },
              'License'        => MSF_LICENSE,
              'Author'         =>
                [
                  'Tavis Ormandy', # Discovery and C exploit
                  'bcoles' # Metasploit
                ],
              'DisclosureDate' => '2015-04-14',
              'Platform'       => [ 'linux' ],
              'Arch'           => [ ARCH_X86, ARCH_X64 ],
              'SessionTypes'   => [ 'shell', 'meterpreter' ],
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_stat
                    stdapi_sys_process_execute
                  ]
                }
              }
            )
          )
        end
        def run
          session.sys.process.execute 'shell', "command"
          passwd_stat = session.fs.file.stat(@chown_file).stathash
        end
      end
    RUBY
  end

  it 'tracks the use of processes' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
          register_options([])
        end
        def run
          target = client.sys.process.open(notepad_process.pid, PROCESS_ALL_ACCESS)
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          target.thread.create(exploit_mem + offset, param_ptr)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.

          targetprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          targetprocess.thread.each_thread do |x|
            if resume
              targetprocess.thread.open(x).resume
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
            else
              targetprocess.thread.open(x).suspend
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
            end
          end

          calc = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          mem  = calc.memory.allocate(32)
                 ^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          calc.memory.write(mem, "1234")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          targetprocess.thread.open(x).resume
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end

        def helper(process)
          shellcode_mem = process.memory.allocate(shellcode_size)
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          process.memory.protect(shellcode_mem)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          process.memory.write(shellcode_mem, shellcode)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_sys_process_attach
                  stdapi_sys_process_memory_allocate
                  stdapi_sys_process_memory_protect
                  stdapi_sys_process_memory_write
                  stdapi_sys_process_thread_create
                  stdapi_sys_process_thread_open
                  stdapi_sys_process_thread_resume
                  stdapi_sys_process_thread_suspend
                ]
              }
            }
          )
          register_options([])
        end
        def run
          target = client.sys.process.open(notepad_process.pid, PROCESS_ALL_ACCESS)
          target.thread.create(exploit_mem + offset, param_ptr)

          targetprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
          targetprocess.thread.each_thread do |x|
            if resume
              targetprocess.thread.open(x).resume
            else
              targetprocess.thread.open(x).suspend
            end
          end

          calc = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
          mem  = calc.memory.allocate(32)
          calc.memory.write(mem, "1234")
          targetprocess.thread.open(x).resume
        end

        def helper(process)
          shellcode_mem = process.memory.allocate(shellcode_size)
          process.memory.protect(shellcode_mem)
          process.memory.write(shellcode_mem, shellcode)
        end
      end
    RUBY
  end

  it 'verfies that mapping commands to expressions also functions correctly' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.upload(@paths['ff'] + new_file, tmp)
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    core_channel_close
                    core_channel_open
                    core_channel_tell
                    core_channel_write
                    stdapi_fs_separator
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.upload(@paths['ff'] + new_file, tmp)
        end
      end
    RUBY
  end

  it 'handles lots of examples' do
    %w[client].each do |keyword|
      code_snippet_with_errors = <<-EOF
        %{keyword}.fs.file.rm(
        ^{keyword}^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
            "some_file"
        )
        %{keyword}.sys.process.get_processes
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.ls("file")
        ^{keyword}^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.load_key(root_key, base_key, file)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.unload_key(root_key,base_key)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.getprivs()
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.create_key(root_key, base_key, perms)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.open_key(root_key, base_key, perms)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.delete_key(root_key, base_key, perms)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.enum_key_direct(root_key, base_key, perms)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.enum_value_direct(root_key, base_key, perms)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.query_value_direct(root_key, base_key, valname, perms)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.set_value_direct(root_key, base_key, valname, %{keyword}.sys.registry.type2str(type), data, perms)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.check_key_exists(root_key, base_key)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.dir.getwd
        ^{keyword}^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.appapi.app_install(out_apk)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.execute
        ^{keyword}^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.stat(@chown_file)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.sysinfo["Computer"]
        ^{keyword}^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.get_processes
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.getenv('TEMP')
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.railgun.memread(@addresses['AcroRd32.exe'] + target['AdobeCollabSyncTrigger'], target['AdobeCollabSyncTriggerSignature'].length)
        ^{keyword}^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.open
        ^{keyword}^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.net.socket.create
        ^{keyword}^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.getprivs
        ^{keyword}^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.getenv('windir')
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.copy("C:\\Windows\\System32\\WSReset.exe", exploit_file)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.getdrivers
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.md5(d[:filename])
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.dir.mkdir(share_dir)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.power.reboot
        ^{keyword}^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.getuid
        ^{keyword}^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.new(taskfile, "wb")
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.stat(@chown_file).stathash
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.android.activity_start('intent:#Intent;launchFlags=0x8000;component=com.android.settings/.ChooseLockGeneric;i.lockscreen.password_type=0;B.confirm_credentials=false;end')
        ^{keyword}^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.net.resolve.resolve_host(name)[:ip]
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.separator
        ^{keyword}^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.exist?(@paths['ff'] + temp_file) && !%{keyword}.fs.file.exist?(@paths['ff'] + org_file)
        _{keyword}                                              ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.search(path, "config.xml", true, -1)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.android.wlan_geolocate
        ^{keyword}^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.webcam.record_mic(datastore['DURATION'])
        ^{keyword}^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.espia.espia_image_get_dev_screen
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.android.set_wallpaper(File.binread(file))
        ^{keyword}^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.steal_token(pid)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.revert_to_self
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.net.config.each_route
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.net.config.each_interface
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.dir.pwd
        ^{keyword}^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.priv.getsystem(technique)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.kiwi.golden_ticket_create(ticket)
        ^{keyword}^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.kiwi.kerberos_ticket_use(ticket)
        ^{keyword}^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.priv.sam_hashes
        ^{keyword}^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.incognito.incognito_list_tokens(0)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.dir.entries(v)
        ^{keyword}^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.kiwi.get_debug_privilege
        ^{keyword}^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.kiwi.creds_all
        ^{keyword}^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.is_system?
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.extapi.wmi.query("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering")
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.registry.open_remote_key(datastore['RHOST'], root_key)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.priv.getsystem
        ^{keyword}^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.extapi.adsi.domain_query(domain, adsi_filter, 255, 255, adsi_fields)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.priv.fs.get_file_mace(datastore['FILE'])
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.priv.fs.set_file_mace(datastore['FILE'], mace["Modified"], mace["Accessed"], mace["Created"], mace["Entry Modified"])
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.extapi.pageant.forward(socket_request_data.first, socket_request_data.first.size)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.dhcp.reset
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.dhcp.load_options(datastore)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.tftp.start
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.dhcp.start
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.tftp.stop
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.dhcp.stop
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.webcam.webcam_start(datastore['INDEX'])
        ^{keyword}^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.webcam.webcam_get_frame(datastore['QUALITY'])
        ^{keyword}^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.webcam.webcam_stop
        ^{keyword}^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.webcam.webcam_list
        ^{keyword}^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.incognito.incognito_impersonate_token(domain_user)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.expand_path(path)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.peinjector.inject_shellcode(param)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.dhcp.load_options(datastore)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.config.getenvs('SYSTEMDRIVE', 'HOMEDRIVE', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432')
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.exist?(net_sarang_path_5)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.dhcp.log.each
        ^{keyword}^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.dir.rmdir(datastore['PATH'])
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.open.name
        ^{keyword}^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.get_processes
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.getpid
        ^{keyword}^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.open(pid, PROCESS_ALL_ACCESS)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.get_processes()
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.kill(process['pid'])
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.execute(cmd, nil, {'Hidden' => true})
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.each_process.find
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.open.pid
        ^{keyword}^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.execute 'script', "command"
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.download("test", "file", opts)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.upload(dst_item, src_item)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.upload_file(@paths['ff'] + new_file, tmp)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.lanattacks.tftp.add_file("update_test",contents)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.download_file("local_path/img", "f_path/img", opts)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.sys.process.execute '/bin/sh', "-c \\"chown root:root \#{@chown_file}\\""
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.chmod(path, mode)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.mv(src_name, dst_name)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.file.sha1(remote)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.fs.mount.show_mount
        ^{keyword}^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        %{keyword}.net.config.add_route(*args)
        ^{keyword}^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
      EOF

      code_snippet_without_error_lines = (
        code_snippet_with_errors
          .lines
          .reject { |line| line.lstrip.start_with?('^{keyword}') || line.lstrip.start_with?('_{keyword}')}
          .join
          .gsub('%{keyword}', keyword)
      )

      expect_offense(<<~RUBY, keyword: keyword)
        class DummyModule
              ^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          def run
  #{code_snippet_with_errors}
          end
        end
      RUBY

      expect_correction(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Compat' => {
                  'Meterpreter' => {
                    'Commands' => %w[
                      android_*
                      appapi_app_install
                      core_channel_close
                      core_channel_eof
                      core_channel_open
                      core_channel_read
                      core_channel_tell
                      core_channel_write
                      espia_image_get_dev_screen
                      extapi_adsi_domain_query
                      extapi_pageant_send_query
                      extapi_wmi_query
                      incognito_impersonate_token
                      incognito_list_tokens
                      kiwi_exec_cmd
                      lanattacks_add_tftp_file
                      lanattacks_dhcp_log
                      lanattacks_reset_dhcp
                      lanattacks_set_dhcp_option
                      lanattacks_start_dhcp
                      lanattacks_start_tftp
                      lanattacks_stop_dhcp
                      lanattacks_stop_tftp
                      peinjector_inject_shellcode
                      priv_elevate_getsystem
                      priv_fs_get_file_mace
                      priv_fs_set_file_mace
                      priv_passwd_get_sam_hashes
                      stdapi_fs_*
                      stdapi_fs_chmod
                      stdapi_fs_delete_dir
                      stdapi_fs_delete_file
                      stdapi_fs_file_copy
                      stdapi_fs_file_expand_path
                      stdapi_fs_file_move
                      stdapi_fs_getwd
                      stdapi_fs_ls
                      stdapi_fs_md5
                      stdapi_fs_mkdir
                      stdapi_fs_mount_show
                      stdapi_fs_search
                      stdapi_fs_separator
                      stdapi_fs_sha1
                      stdapi_fs_stat
                      stdapi_net_config_add_route
                      stdapi_net_config_get_interfaces
                      stdapi_net_config_get_routes
                      stdapi_net_resolve_host
                      stdapi_railgun_*
                      stdapi_registry_check_key_exists
                      stdapi_registry_create_key
                      stdapi_registry_delete_key
                      stdapi_registry_enum_key_direct
                      stdapi_registry_enum_value_direct
                      stdapi_registry_load_key
                      stdapi_registry_open_key
                      stdapi_registry_open_remote_key
                      stdapi_registry_query_value_direct
                      stdapi_registry_set_value_direct
                      stdapi_registry_unload_key
                      stdapi_sys_config_driver_list
                      stdapi_sys_config_getenv
                      stdapi_sys_config_getprivs
                      stdapi_sys_config_getsid
                      stdapi_sys_config_getuid
                      stdapi_sys_config_rev2self
                      stdapi_sys_config_steal_token
                      stdapi_sys_config_sysinfo
                      stdapi_sys_power_exitwindows
                      stdapi_sys_process_attach
                      stdapi_sys_process_execute
                      stdapi_sys_process_get_processes
                      stdapi_sys_process_getpid
                      stdapi_sys_process_kill
                      stdapi_webcam_*
                    ]
                  }
                }
              )
            )
          end

          def run
  #{code_snippet_without_error_lines}
          end
        end
      RUBY
    end
  end

  it 'autocorrects only valid meterpreter commands' do
    ignored_commands = []
    valid_meterpreter_command_names = Rex::Post::Meterpreter::CommandMapper.get_command_names
    autocorrected_meterpreter_command_names = described_class.new.mappings.flat_map { |mapping| mapping[:commands] }.flatten.uniq

    # This allows entire libraries to be ignore if the commands are being called with a wildcard
    autocorrected_meterpreter_command_names.each do |command|
      ignored_commands << command if command.end_with?('_*')
    end

    invalid_autocorrected_command_names = autocorrected_meterpreter_command_names - valid_meterpreter_command_names - ignored_commands
    expect(invalid_autocorrected_command_names).to be_empty
  end

  it 'verifies that each command ID has an associated matcher' do
    valid_meterpreter_command_names = Rex::Post::Meterpreter::CommandMapper.get_command_names
    autocorrected_meterpreter_command_names = described_class.new.mappings.flat_map { |mapping| mapping[:commands] }
    api_commands_without_matchers = valid_meterpreter_command_names - autocorrected_meterpreter_command_names.flatten.uniq

    # Handle wildcard matchers, i.e. `stdapi_railgun_*`
    api_commands_handled_via_wildcards = []
    autocorrected_meterpreter_command_names.each do |command|
      if command.end_with?('_*')
        prefix = command.gsub("_*", "")
        api_commands_without_matchers.each do |unmatched_command|
          if unmatched_command.start_with?(prefix)
            api_commands_handled_via_wildcards << unmatched_command
          end
        end
      end
    end

    api_commands_without_matchers -= api_commands_handled_via_wildcards

    # Remove known core command ids
    ignored_core_command_ids = [
       "core_channel_interact",
       "core_channel_seek",
       "core_console_write",
       "core_enumextcmd",
       "core_get_session_guid",
       "core_loadlib",
       "core_machine_id",
       "core_migrate",
       "core_native_arch",
       "core_negotiate_tlv_encryption",
       "core_patch_url",
       "core_pivot_add",
       "core_pivot_remove",
       "core_pivot_session_died",
       "core_set_session_guid",
       "core_set_uuid",
       "core_shutdown",
       "core_transport_add",
       "core_transport_change",
       "core_transport_getcerthash",
       "core_transport_list",
       "core_transport_next",
       "core_transport_prev",
       "core_transport_remove",
       "core_transport_setcerthash",
       "core_transport_set_timeouts",
       "core_transport_sleep",
       "core_pivot_session_new",
    ]

    api_commands_without_matchers -= ignored_core_command_ids

    # Remove additional command ids
    other_ignored_command_ids = [
      "stdapi_net_tcp_channel_open",
      "stdapi_net_socket_tcp_shutdown"
    ]

    api_commands_without_matchers -= other_ignored_command_ids
    expect(api_commands_without_matchers).to be_empty
  end
end

