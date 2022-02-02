# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_disclosure_date_present'

RSpec.describe RuboCop::Cop::Lint::ModuleDisclosureDatePresent do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  it 'accepts a DisclosureDate being present' do
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
              'DisclosureDate' => '2009-06-25'
            )
          )
        end
      end
    RUBY
  end

  it 'requires a DisclosureDate to be present when keys are present' do
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
              ^^^^^^ Module is missing the required DisclosureDate information
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'requires DisclosureDate to be present when no keys are present' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              {}
              ^^ Module is missing the required DisclosureDate information
            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end
end
