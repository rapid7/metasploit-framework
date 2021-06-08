require 'spec_helper'
require 'rubocop/cop/lint/meterpreter_commands_dependencies'

RSpec.describe RuboCop::Cop::Lint::MeterpreterCommandDependencies, :config do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  it 'generates a list of meterpreter command dependencies based off meterpreter api calls in modules`' do
    expect_offense(<<~RUBY)
    client.fs.file.rm
    ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
    RUBY

    expect_correction(<<~RUBY)
    stdapi_fs_rm
    RUBY
  end
end

