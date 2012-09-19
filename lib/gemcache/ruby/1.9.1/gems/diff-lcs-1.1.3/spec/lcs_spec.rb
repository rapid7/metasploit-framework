# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe "Diff::LCS.LCS and Diff::LCS.__lcs" do
  include Diff::LCS::SpecHelper::Matchers

  it "should return the correct raw values from Diff::LCS.__lcs" do
    res = Diff::LCS.__lcs(seq1, seq2)
    # The result of the LCS (less the +nil+ values) must be as long as the
    # correct result.
    res.compact.size.should == correct_lcs.size
    res.should correctly_map_sequence(seq1).to_other_sequence(seq2)

    # Compact these transformations and they should be the correct LCS.
    x_seq1 = (0...res.size).map { |ix| res[ix] ? seq1[ix] : nil }.compact
    x_seq2 = (0...res.size).map { |ix| res[ix] ? seq2[res[ix]] : nil }.compact

    x_seq1.should == correct_lcs
    x_seq2.should == correct_lcs
  end

  it "should return the correct compacted values from Diff::LCS.LCS" do
    res = Diff::LCS.LCS(seq1, seq2)
    res.should == correct_lcs
    res.compact.should == res
  end

  it "should be transitive" do
    res = Diff::LCS.LCS(seq2, seq1)
    res.should == correct_lcs
    res.compact.should == res
  end
end

# vim: ft=ruby
