require 'rex/parser/ini'

RSpec.describe Rex::Parser::Ini do
  let(:ini_contents) { <<EOF
# global comment
global settting = blah
[foo]
a = b
[bar]
b = c

[baf]
c = d
EOF
  }

  let(:ini) { described_class.from_s(ini_contents) }

  context "#each_group" do
    it "enumerates the groups" do
      groups = []
      ini.each_group { |group| groups << group }
      expect(groups).to eq(%w(foo bar baf))
    end
  end

  context "#each_key" do
    it "enumerates the groups" do
      groups = []
      ini.each_key.map { |group| groups << group }
      expect(groups).to eq(%w(foo bar baf))
    end
  end
end
