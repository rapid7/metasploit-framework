require 'spec_helper'
require 'rubocop/cop/lint/deprecated_gem_version'

RSpec.describe RuboCop::Cop::Lint::DeprecatedGemVersion do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  it 'corrects `Gem::Version`' do
    expect_offense(<<~RUBY)
      Gem::Version
      ^^^^^^^^^^^^ Use `Rex::Version` instead of `Gem::Version`.
    RUBY

    expect_correction(<<~RUBY)
      Rex::Version
    RUBY
  end

  it 'corrects `Gem::Version.new`' do
    expect_offense(<<~RUBY)
      Gem::Version.new("1.0.0")
      ^^^^^^^^^^^^ Use `Rex::Version` instead of `Gem::Version`.
    RUBY

    expect_correction(<<~RUBY)
      Rex::Version.new("1.0.0")
    RUBY
  end

  it 'corrects `::Gem::Version`' do
    expect_offense(<<~RUBY)
      ::Gem::Version
      ^^^^^^^^^^^^^^ Use `Rex::Version` instead of `Gem::Version`.
    RUBY

    expect_correction(<<~RUBY)
      ::Rex::Version
    RUBY
  end

  it 'does not correct `Abc::Gem::Version`' do
    expect_no_offenses(<<~RUBY)
      Abc::Gem::Version
    RUBY
  end
end
