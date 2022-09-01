# frozen_string_literal: true
require 'spec_helper'
require 'rubocop/cop/layout/module_hash_values_on_same_line'

RSpec.describe RuboCop::Cop::Layout::ModuleHashValuesOnSameLine do
  subject(:cop) { described_class.new(config) }
  let(:config) do
    RuboCop::Config.new(
      'Layout/IndentationWidth' => {
        'Width' => indentation_width
      })
  end
  let(:indentation_width) { 2 }

  it 'accepts hash values being on the same line' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'          => 'Simple module name',
              'Description'   => 'Lorem ipsum dolor sit amet',
              'Author'        => [ 'example1', 'example2' ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'accepts hash values across multipline lines' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name'          => 'Simple module name',
              'Description'   => 'Lorem ipsum dolor sit amet',
              'Author'        => [
                'example1',
                'example2'
              ],
              'License'       => MSF_LICENSE,
              'Platform'      => 'win',
              'Arch'          => ARCH_X86,
            )
          )
        end
      end
    RUBY
  end

  it 'registers an offence when a hash value is on its own line' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        =>
              [ 'example1', 'example2' ],
              ^ a hash value should open on the same line as its key
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
        end
      end
    RUBY
  end

  it 'ensures merge_info functions are handled correctly' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(merge_info(
            info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        =>
              [
              ^ a hash value should open on the same line as its key
                'example1',
                'example2'
              ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
          register_options([])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(merge_info(
            info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author' => [
                'example1',
                'example2'
              ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
          register_options([])
        end
      end
    RUBY
  end

  it 'handles comments between the new lines' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(merge_info(
            info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author' => [
                'example1',
                'example2'
              ],
            'Notes' => # Note that reliability isn't included here, as technically the exploit can only
            # only be run once, after which the service crashes.
            {
            ^ a hash value should open on the same line as its key
              'SideEffects' => [ CONFIG_CHANGES ], # This module will change the configuration by
              # resetting the router to the default factory password.
              'Stability' => [ CRASH_SERVICE_DOWN ] # This module will crash the target service after it is run.
            },
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
          register_options([])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(merge_info(
            info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author' => [
                'example1',
                'example2'
              ],
            # Note that reliability isn't included here, as technically the exploit can only
            # only be run once, after which the service crashes.
            'Notes' => {
              'SideEffects' => [ CONFIG_CHANGES ], # This module will change the configuration by
              # resetting the router to the default factory password.
              'Stability' => [ CRASH_SERVICE_DOWN ] # This module will crash the target service after it is run.
            },
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
          register_options([])
        end
      end
    RUBY
  end

  it 'handles an implicit hash' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author' => [
                'example1',
                'example2'
              ],
            'Notes' => # Note that reliability isn't included here, as technically the exploit can only
            # only be run once, after which the service crashes.
            {
            ^ a hash value should open on the same line as its key
              'SideEffects' => [ CONFIG_CHANGES ], # This module will change the configuration by
              # resetting the router to the default factory password.
              'Stability' => [ CRASH_SERVICE_DOWN ] # This module will crash the target service after it is run.
            },
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
          register_options([])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author' => [
                'example1',
                'example2'
              ],
            # Note that reliability isn't included here, as technically the exploit can only
            # only be run once, after which the service crashes.
            'Notes' => {
              'SideEffects' => [ CONFIG_CHANGES ], # This module will change the configuration by
              # resetting the router to the default factory password.
              'Stability' => [ CRASH_SERVICE_DOWN ] # This module will crash the target service after it is run.
            },
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
          register_options([])
        end
      end
    RUBY
  end

  it 'handles an implicit hash without additional instructions' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author' => [
                'example1',
                'example2'
              ],
            'Notes' => # Note that reliability isn't included here, as technically the exploit can only
            # only be run once, after which the service crashes.
            {
            ^ a hash value should open on the same line as its key
              'SideEffects' => [ CONFIG_CHANGES ], # This module will change the configuration by
              # resetting the router to the default factory password.
              'Stability' => [ CRASH_SERVICE_DOWN ] # This module will crash the target service after it is run.
            },
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author' => [
                'example1',
                'example2'
              ],
            # Note that reliability isn't included here, as technically the exploit can only
            # only be run once, after which the service crashes.
            'Notes' => {
              'SideEffects' => [ CONFIG_CHANGES ], # This module will change the configuration by
              # resetting the router to the default factory password.
              'Stability' => [ CRASH_SERVICE_DOWN ] # This module will crash the target service after it is run.
            },
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            )
        end
      end
    RUBY
  end

  it 'still registers offenses if register_options is present' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(info,
            'Name'          => 'Simple module name',
            'Description'   => 'Lorem ipsum dolor sit amet',
            'Author'        =>
                    [ 'example1', 'example2' ],
                    ^ a hash value should open on the same line as its key
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X86,
            ))
          register_options([])
        end
      end
    RUBY
  end
end
