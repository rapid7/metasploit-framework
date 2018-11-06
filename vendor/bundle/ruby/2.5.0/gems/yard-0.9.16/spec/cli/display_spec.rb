# frozen_string_literal: true

RSpec.describe YARD::CLI::Display do
  before do
    allow(Registry).to receive(:load)
    @object = CodeObjects::ClassObject.new(:root, :Foo)
    @object.docstring = 'Foo bar'
  end

  it "displays an object" do
    YARD::CLI::Display.run('-f', 'text', 'Foo')
    expect(log.io.string.strip).to eq(@object.format.strip)
  end

  it "wraps output with -l (defaulting to layout)" do
    YARD::CLI::Display.run('-l', '-f', 'html', 'Foo')
    formatted_output = @object.format(:format => :html).strip
    actual_output = log.io.string.strip
    expect(actual_output).not_to eq(formatted_output)
    expect(actual_output).to include(formatted_output)
  end

  it "wraps output with --layout onefile" do
    YARD::CLI::Display.run('--layout', 'onefile', '-f', 'html', 'Foo')
    formatted_output = @object.format(:format => :html).strip
    actual_output = log.io.string.strip
    expect(actual_output).not_to eq(formatted_output)
    expect(actual_output).to include(formatted_output)
  end
end
