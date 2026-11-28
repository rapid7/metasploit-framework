# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe Rex::Ui::Text::Output::File do
  it 'supports the text output color settings while writing plain text' do
    Dir.mktmpdir do |directory|
      path = File.join(directory, 'console.log')
      output = described_class.new(path)

      expect(output.config[:color]).to eq(:auto)
      output.disable_color
      expect(output.config[:color]).to be(false)
      output.enable_color
      expect(output.config[:color]).to be(true)
      output.print_line('%redmessage%clr')
      expect(File.binread(path)).to eq("message\n")
    ensure
      output&.close
    end
  end
end
