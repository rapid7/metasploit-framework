# frozen_string_literal: trueAdd commentMore actions

require 'rubocop/cop/lint/detect_metadata_trailing_leading_whitespace'
require 'rubocop/rspec/support'

RSpec.describe RuboCop::Cop::Lint::DetectMetadataTrailingLeadingWhitespace, :config do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }

  it 'registers an offense for leading/trailing whitespace in Name' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'Name' => ' value ',
                    ^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in Author (array)' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'Author' => [
            ' author ',
            ^^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
          ],
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in License' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'License' => ' MSF_LICENSE ',
                       ^^^^^^^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in Privileged' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'Privileged' => ' true ',
                          ^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in DefaultOptions (hash)' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'DefaultOptions' => {
            'WfsDelay' => ' 10 ',
                          ^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
          },
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in References (array of arrays)' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'References' => [
            [ ' CVE ', ' 1999-0504 ' ],
              ^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
                       ^^^^^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
          ],
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in Platform' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'Platform' => ' win ',
                        ^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in Targets (array of arrays)' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'Targets' => [
            [ ' Automatic ', { 'Arch' => [ ' ARCH_X86 ', ' ARCH_X64 ' ] } ],
              ^^^^^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
                                                         ^^^^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
                                           ^^^^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
          ],
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in DefaultTarget' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'DefaultTarget' => ' 0 ',
                             ^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
        ))
      end
    RUBY
  end

  it 'registers an offense for leading/trailing whitespace in DisclosureDate' do
    expect_offense(<<~RUBY)
      def initialize(info = {})
        super(update_info(info,
          'DisclosureDate' => ' 1999-01-01 ',
                              ^^^^^^^^^^^^^^ Lint/DetectMetadataTrailingLeadingWhitespace: Metadata key or value has leading or trailing whitespace.
        ))
      end
    RUBY
  end
end
