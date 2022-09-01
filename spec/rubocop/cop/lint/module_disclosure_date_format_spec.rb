# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_disclosure_date_format'

RSpec.describe RuboCop::Cop::Lint::ModuleDisclosureDateFormat do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  before(:each) do
    Timecop.freeze(2020, 10, 02, 12)
  end

  after(:example) do
    Timecop.return
  end

  it 'accepts a valid DisclosureDate' do
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

  it 'accepts a "Generic Payload Handler" having no DisclosureDate' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Generic Payload Handler',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86
            )
          )
        end
      end
    RUBY
  end

  it 'rejects invalid DisclosureDate values' do
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
                                  ^^^^^^^^^^^ Modules should specify a DisclosureDate with the required format '%Y-%m-%d', for example '2020-10-02'

            )
          )
        end
      end
    RUBY
    expect_no_corrections
  end

  it 'provides an autocorrection when the DisclosureDate can safely be converted to the required format' do
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
              'DisclosureDate' => 'Dec 7 2007'
                                  ^^^^^^^^^^^^ Modules should specify a DisclosureDate with the required format '%Y-%m-%d', for example '2020-10-02'
            )
          )
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
              'DisclosureDate' => '2007-12-07'
            )
          )
        end
      end
    RUBY
  end
end
