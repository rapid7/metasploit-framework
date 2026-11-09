require 'spec_helper'
require 'rubocop/cop/lint/module_defanged_mode_description'

RSpec.describe RuboCop::Cop::Lint::ModuleDefangedModeDescription do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }
  let(:message) { 'Lint/ModuleDefangedModeDescription: Explain the module-specific risk prevented by defanged mode in the option description.' }

  it 'flags the stock description used by existing modules' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true, 'Run in defanged mode', true])
                                         ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'recognizes the legacy uppercase option name' do
    expect_offense(<<~RUBY)
      OptBool.new('DEFANGED_MODE', [true, 'Run in defanged mode', true])
                                          ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'recognizes the existing OptString declaration' do
    expect_offense(<<~RUBY)
      OptString.new('DefangedMode', [true, 'Run in defanged mode', true])
                                           ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'recognizes namespaced constructors in normal and advanced registrations' do
    expect_offense(<<~RUBY)
      register_options([Msf::OptBool.new('DefangedMode', [true, 'Run in defanged mode', true])])
                                                                ^^^^^^^^^^^^^^^^^^^^^^ #{message}
      register_advanced_options([::Msf::OptString.new('DefangedMode', [true, 'Run in defanged mode', true])])
                                                                             ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'normalizes case, whitespace and terminal punctuation' do
    expect_offense(<<~'RUBY')
      OptBool.new('DefangedMode', [true, "  RUN\tIN  DEFANGED MODE!  ", true])
                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDefangedModeDescription: Explain the module-specific risk prevented by defanged mode in the option description.
    RUBY
  end

  it 'flags a missing description argument' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode')
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'flags an attribute array without a description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true])
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'flags an explicit nil description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true, nil, true])
                                         ^^^ #{message}
    RUBY
  end

  it 'flags an empty description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true, '', true])
                                         ^^ #{message}
    RUBY
  end

  it 'flags whitespace-only descriptions' do
    expect_offense(<<~'RUBY')
      OptBool.new('DefangedMode', [true, " \t\n", true])
                                         ^^^^^^^ Lint/ModuleDefangedModeDescription: Explain the module-specific risk prevented by defanged mode in the option description.
    RUBY
  end

  it 'flags a stock description supplied as a string argument' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', 'Run in defanged mode', default: true)
                                  ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'flags a stock keyword description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', required: true, desc: 'Run in defanged mode', default: true)
                                                        ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'flags keyword arguments without a description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', required: true, default: true)
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'flags an explicit nil keyword description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', desc: nil)
                                        ^^^ #{message}
    RUBY
  end

  it 'uses the positional description ahead of a meaningful keyword description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true, 'Run in defanged mode', true], desc: 'Prevent file deletion')
                                         ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'does not use a keyword fallback for an empty positional description' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true, '', true], desc: 'Prevent file deletion')
                                         ^^ #{message}
    RUBY
  end

  it 'uses the keyword fallback when the array description is nil' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true, nil, true], desc: 'Run in defanged mode')
                                                           ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'accepts module-specific descriptions with or without the stock prefix' do
    expect_no_offenses(<<~RUBY)
      OptBool.new('DefangedMode', [true, 'Prevent exploitation that deletes the target file', true])
      OptBool.new('DEFANGED_MODE', [true, 'Run in defanged mode to avoid changing the root password', true])
      OptString.new('DefangedMode', [true, 'Prevent changes to local network forwarding', true])
    RUBY
  end

  it 'accepts descriptions through each supported OptBase argument form' do
    expect_no_offenses(<<~RUBY)
      OptBool.new('DefangedMode', 'Prevent file deletion', default: true)
      OptBool.new('DefangedMode', desc: 'Prevent file deletion', default: true)
      OptBool.new('DefangedMode', [], desc: 'Prevent file deletion')
      OptBool.new('DefangedMode', [true], desc: 'Prevent file deletion')
      OptBool.new('DefangedMode', [true, nil, true], desc: 'Prevent file deletion')
      OptBool.new('DefangedMode', [true, false, true], desc: 'Prevent file deletion')
    RUBY
  end

  it 'accepts a meaningful positional string ahead of a generic keyword description' do
    expect_no_offenses(<<~RUBY)
      OptBool.new('DefangedMode', 'Prevent file deletion', desc: 'Run in defanged mode')
      OptBool.new('DefangedMode', [true, 'Prevent file deletion', true], desc: 'Run in defanged mode')
    RUBY
  end

  it 'leaves dynamic names, descriptions and attributes for review' do
    expect_no_offenses(<<~'RUBY')
      OptBool.new(option_name, [true, 'Run in defanged mode', true])
      OptBool.new('DefangedMode', [true, description, true])
      OptBool.new('DefangedMode', [true, "Prevent changes to #{target_file}", true])
      OptBool.new('DefangedMode', attributes)
      OptBool.new('DefangedMode', [*attributes])
      OptBool.new('DefangedMode', **option_attributes)
      OptBool.new('DefangedMode', [true, nil, true], **option_attributes)
    RUBY
  end

  it 'still checks a positional description when keyword arguments are dynamic' do
    expect_offense(<<~RUBY)
      OptBool.new('DefangedMode', [true, 'Run in defanged mode', true], **option_attributes)
                                         ^^^^^^^^^^^^^^^^^^^^^^ #{message}
    RUBY
  end

  it 'ignores unrelated options and constructors' do
    expect_no_offenses(<<~RUBY)
      OptBool.new('AutoCheck', [true, '', true])
      OptBool.new('DefangedDetection', [true, '', true])
      Other::OptBool.new('DefangedMode', [true, '', true])
      Widget.new('DefangedMode')
      OptBool.new
      new('DefangedMode')
      datastore['DefangedMode']
    RUBY
  end
end
