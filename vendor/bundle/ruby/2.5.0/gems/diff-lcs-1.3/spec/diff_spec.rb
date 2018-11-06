# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe Diff::LCS, ".diff" do
  include Diff::LCS::SpecHelper::Matchers

  it "correctly diffs seq1 to seq2" do
    diff_s1_s2 = Diff::LCS.diff(seq1, seq2)
    expect(change_diff(correct_forward_diff)).to eq(diff_s1_s2)
  end

  it "correctly diffs seq2 to seq1" do
    diff_s2_s1 = Diff::LCS.diff(seq2, seq1)
    expect(change_diff(correct_backward_diff)).to eq(diff_s2_s1)
  end

  it "correctly diffs against an empty sequence" do
    diff = Diff::LCS.diff(word_sequence, [])
    correct_diff = [
      [ [ '-', 0, 'abcd'           ],
        [ '-', 1, 'efgh'           ],
        [ '-', 2, 'ijkl'           ],
        [ '-', 3, 'mnopqrstuvwxyz' ] ]
    ]

    expect(change_diff(correct_diff)).to eq(diff)

    diff = Diff::LCS.diff([], word_sequence)
    correct_diff.each { |hunk| hunk.each { |change| change[0] = '+' } }
    expect(change_diff(correct_diff)).to eq(diff)
  end

  it "correctly diffs 'xx' and 'xaxb'" do
    left = 'xx'
    right = 'xaxb'
    expect(Diff::LCS.patch(left, Diff::LCS.diff(left, right))).to eq(right)
  end

  it "returns an empty diff with (hello, hello)" do
    expect(Diff::LCS.diff(hello, hello)).to be_empty
  end

  it "returns an empty diff with (hello_ary, hello_ary)" do
    expect(Diff::LCS.diff(hello_ary, hello_ary)).to be_empty
  end
end
