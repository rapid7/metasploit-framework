# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

if String.method_defined?(:encoding)
  require 'diff/lcs/hunk'

  describe Diff::LCS::Hunk do
    let(:old_data) { ["Tu avec carté {count} itém has".encode('UTF-16LE')] }
    let(:new_data) { ["Tu avec carte {count} item has".encode('UTF-16LE')] }
    let(:pieces)   { Diff::LCS.diff old_data, new_data }
    let(:hunk)     { Diff::LCS::Hunk.new(old_data, new_data, pieces[0], 3, 0) }

    it 'produces a unified diff from the two pieces' do
      expected = (<<-EOD.gsub(/^\s+/,'').encode('UTF-16LE').chomp)
        @@ -1,2 +1,2 @@
        -Tu avec carté {count} itém has
        +Tu avec carte {count} item has
      EOD

      expect(hunk.diff(:unified)).to eq(expected)
    end

    it 'produces a context diff from the two pieces' do
      expected = (<<-EOD.gsub(/^\s+/,'').encode('UTF-16LE').chomp)
        ***************
        *** 1,2 ****
        !Tu avec carté {count} itém has
        --- 1,2 ----
        !Tu avec carte {count} item has
      EOD

      expect(hunk.diff(:context)).to eq(expected)
    end

    it 'produces an old diff from the two pieces' do
      expected = (<<-EOD.gsub(/^ +/,'').encode('UTF-16LE').chomp)
        1,2c1,2
        < Tu avec carté {count} itém has
        ---
        > Tu avec carte {count} item has

      EOD

      expect(hunk.diff(:old)).to eq(expected)
    end

    it 'produces a reverse ed diff from the two pieces' do
      expected = (<<-EOD.gsub(/^ +/,'').encode('UTF-16LE').chomp)
        c1,2
        Tu avec carte {count} item has
        .

      EOD

      expect(hunk.diff(:reverse_ed)).to eq(expected)
    end

    context 'with empty first data set' do
      let(:old_data) { [] }

      it 'produces a unified diff' do
        expected = (<<-EOD.gsub(/^\s+/,'').encode('UTF-16LE').chomp)
          @@ -1 +1,2 @@
          +Tu avec carte {count} item has
        EOD

        expect(hunk.diff(:unified)).to eq(expected)
      end
    end
  end
end
