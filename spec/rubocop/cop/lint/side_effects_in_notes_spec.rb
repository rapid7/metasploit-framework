# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/side_effects_in_notes'

RSpec.describe RuboCop::Cop::Lint::SideEffectsInNotes do
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

  it 'requires SideEffects to be present when no keys are present' do
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
                         ^^ Module is missing SideEffects [...]
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires SideEffects to be present when keys are present' do
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
              'Notes' => {'Stability' => [CRASH_SAFE],}
                          ^^^^^^^^^^^ Module is missing SideEffects [...]
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'SideEffects can be an empty array' do
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
                'SideEffects' => []
              }
            )
          )
        end
      end
    RUBY
  end

  it 'SideEffects can be a single item in an array' do
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
                'SideEffects' => [IOC_IN_LOGS]
              }
            )
          )
        end
      end
    RUBY
  end

  it 'SideEffects can be a multiple items in an array' do
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
                'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS]
              }
            )
          )
        end
      end
    RUBY
  end
end
