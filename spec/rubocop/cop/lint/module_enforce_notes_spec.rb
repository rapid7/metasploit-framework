# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_enforce_notes'

RSpec.describe RuboCop::Cop::Lint::ModuleEnforceNotes do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  it 'requires Notes to be present when keys are present' do
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
              ^^^^^^ Module is missing the Notes section [...]
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires Notes to be present when no keys are present' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              {}
              ^^ Module is missing the Notes section [...]
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires Stability, Reliability and SideEffects to be present when no keys are present' do
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
              'Notes' => {}
                         ^^ Module is missing Stability, Reliability and SideEffects [...]
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires Stability, Reliability and SideEffects to be present when keys are present' do
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
              'Notes' => {'SomeKey' => [some_value],}
                          ^^^^^^^^^ Module is missing Stability, Reliability and SideEffects [...]
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires Stability to be present even when SideEffects and Reliability are present' do
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
              'Notes' => {
                'SideEffects' => [IOC_IN_LOGS],
                'Reliability' => [FIRST_ATTEMPT_FAIL]
                ^^^^^^^^^^^^^ Module is missing Stability [...]
              }
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires SideEffects to be present even when Stability and Reliability are present' do
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
              'Notes' => {
                'Stability' => [CRASH_SAFE],
                'Reliability' => [FIRST_ATTEMPT_FAIL]
                ^^^^^^^^^^^^^ Module is missing SideEffects [...]
              }
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires Reliability to be present even when Stability and SideEffects are present' do
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
              'Notes' => {
                'Stability' => [CRASH_SAFE],
                'SideEffects' => [IOC_IN_LOGS],
                ^^^^^^^^^^^^^ Module is missing Reliability [...]
              }
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'Stability, Reliability and SideEffects can be empty arrays' do
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
              'Notes' => {
                'Stability' => [],
                'SideEffects' => [],
                'Reliability' => []
              }
            )
          )
        end
      end
    RUBY
  end

  it 'Stability, Reliability and SideEffects can be a single item in an array' do
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
              'Notes' => {
                'Stability' => [CRASH_SAFE],
                'SideEffects' => [IOC_IN_LOGS],
                'Reliability' => [FIRST_ATTEMPT_FAIL]
              }
            )
          )
        end
      end
    RUBY
  end

  it 'Stability, Reliability and SideEffects can be a multiple items in an array' do
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
              'Notes' => {
                'Stability' => [CRASH_SAFE, SECOND_ITEM],
                'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
                'Reliability' => [FIRST_ATTEMPT_FAIL, SECOND_ITEM]
              }
            )
          )
        end
      end
    RUBY
  end
end
