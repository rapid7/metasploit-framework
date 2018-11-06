# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe Diff::LCS::Internals, ".lcs" do
  include Diff::LCS::SpecHelper::Matchers

  it "returns a meaningful LCS array with (seq1, seq2)" do
    res = Diff::LCS::Internals.lcs(seq1, seq2)
    # The result of the LCS (less the +nil+ values) must be as long as the
    # correct result.
    expect(res.compact.size).to eq(correct_lcs.size)
    expect(res).to correctly_map_sequence(seq1).to_other_sequence(seq2)

    # Compact these transformations and they should be the correct LCS.
    x_seq1 = (0...res.size).map { |ix| res[ix] ? seq1[ix] : nil }.compact
    x_seq2 = (0...res.size).map { |ix| res[ix] ? seq2[res[ix]] : nil }.compact

    expect(x_seq1).to eq(correct_lcs)
    expect(x_seq2).to eq(correct_lcs)
  end

  it "returns all indexes with (hello, hello)" do
    expect(Diff::LCS::Internals.lcs(hello, hello)).to \
      eq((0...hello.size).to_a)
  end

  it "returns all indexes with (hello_ary, hello_ary)" do
    expect(Diff::LCS::Internals.lcs(hello_ary, hello_ary)).to \
      eq((0...hello_ary.size).to_a)
  end
end

describe Diff::LCS, ".LCS" do
  include Diff::LCS::SpecHelper::Matchers

  it "returns the correct compacted values from Diff::LCS.LCS" do
    res = Diff::LCS.LCS(seq1, seq2)
    expect(res).to eq(correct_lcs)
    expect(res.compact).to eq(res)
  end

  it "is transitive" do
    res = Diff::LCS.LCS(seq2, seq1)
    expect(res).to eq(correct_lcs)
    expect(res.compact).to eq(res)
  end

  it "returns %W(h e l l o) with (hello, hello)" do
    expect(Diff::LCS.LCS(hello, hello)).to eq(hello.split(//))
  end

  it "returns hello_ary with (hello_ary, hello_ary)" do
    expect(Diff::LCS.LCS(hello_ary, hello_ary)).to eq(hello_ary)
  end
end
