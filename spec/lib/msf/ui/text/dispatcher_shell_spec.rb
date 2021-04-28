require 'spec_helper'

RSpec.describe Rex::Ui::Text::DispatcherShell do
  let(:prompt) { "%undmsf6%clr" }
  let(:prompt_char) { "%clr>" }
  let(:subject) do
    dummy_class = Class.new
    dummy_class.include described_class
    dummy_class.new(prompt, prompt_char)
  end

  # Tests added to verify regex correctly returns correct values in various situations
  describe '#shellsplitex' do
    [
      { input: "dir", expected: { quote: nil, words: ["dir"] } },
      { input: "dir \"/\"", expected: {:quote=>nil, :words=>["dir", "/"]} },
      { input: "dir \"/", expected: {:quote=>"\"", :words=>["dir", "/"]} },
      { input: "dir \"/Program", expected: {:quote=>"\"", :words=>["dir", "/Program"]} },
      { input: "dir \"/Program/", expected: {:quote=>"\"", :words=>["dir", "/Program/"]} },
      { input: "dir C:\\Pro", expected: {:quote=>nil, :words=>["dir", "C:\\Pro"]} },
      { input: "dir \"C:\\Pro\"", expected: {:quote=>nil, :words=>["dir", "C:\\Pro"]} },
      { input: "dir 'C:\\Pro'", expected: {:quote=>nil, :words=>["dir", "C:\\Pro"]} },
      { input: "dir 'C:\\ProgramData\\jim\\bob.rb'", expected: {:quote=>nil, :words=>["dir", "C:\\ProgramData\\jim\\bob.rb"]} },
      { input: "dir 'C:\\ProgramData\\jim\\'", expected: {:quote=>nil, :words=>["dir", "C:\\ProgramData\\jim\\"]} },
      { input: "dir \"C:\\Pro", expected: { quote: "\"", words: ["dir", "C:\\Pro"] } },
      { input: "dir \"C: \\Pro", expected: { quote: "\"", words: ["dir", "C: \\Pro"] } },
      { input: "dir \"C:\\Program F", expected: { quote: "\"", words: ["dir", "C:\\Program F"] } }
    ].each do |test|
      it { expect(subject.shellsplitex(test[:input])).to eql(test[:expected]) }
    end
  end
end
