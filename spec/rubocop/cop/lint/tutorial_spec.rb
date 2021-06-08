require 'spec_helper'
require 'rubocop/cop/lint/tutorial'

RSpec.describe RuboCop::Cop::Lint::SimplifyNotEmptyWithAny, :config do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  it 'corrects `!a.empty?`' do
    expect_offense(<<~RUBY)
    hello world
    ^^^^^^^^^^^ Use `.any?` and remove the negation part.
    RUBY

    expect_correction(<<~RUBY)
    Hello World!
    RUBY
  end
end
