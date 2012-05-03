# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe "Diff::LCS.traverse_sequences" do
  describe "callback with no finishers" do
    before(:each) do
      @callback_s1_s2 = simple_callback_no_finishers
      Diff::LCS.traverse_sequences(seq1, seq2, @callback_s1_s2)

      @callback_s2_s1 = simple_callback_no_finishers
      Diff::LCS.traverse_sequences(seq2, seq1, @callback_s2_s1)
    end

    it "should have the correct LCS result on left-matches" do
      @callback_s1_s2.matched_a.should == correct_lcs
      @callback_s2_s1.matched_a.should == correct_lcs
    end

    it "should have the correct LCS result on right-matches" do
      @callback_s1_s2.matched_b.should == correct_lcs
      @callback_s2_s1.matched_b.should == correct_lcs
    end

    it "should have the correct skipped sequences for the left sequence" do
      @callback_s1_s2.discards_a.should == skipped_seq1
      @callback_s2_s1.discards_a.should == skipped_seq2
    end

    it "should have the correct skipped sequences for the right sequence" do
      @callback_s1_s2.discards_b.should == skipped_seq2
      @callback_s2_s1.discards_b.should == skipped_seq1
    end

    it "should not have anything done markers from the left or right sequences" do
      @callback_s1_s2.done_a.should be_empty
      @callback_s1_s2.done_b.should be_empty
      @callback_s2_s1.done_a.should be_empty
      @callback_s2_s1.done_b.should be_empty
    end
  end

  describe "callback with finisher" do
    before(:each) do
      @callback_s1_s2 = simple_callback
      Diff::LCS.traverse_sequences(seq1, seq2, @callback_s1_s2)
      @callback_s2_s1 = simple_callback
      Diff::LCS.traverse_sequences(seq2, seq1, @callback_s2_s1)
    end

    it "should have the correct LCS result on left-matches" do
      @callback_s1_s2.matched_a.should == correct_lcs
      @callback_s2_s1.matched_a.should == correct_lcs
    end

    it "should have the correct LCS result on right-matches" do
      @callback_s1_s2.matched_b.should == correct_lcs
      @callback_s2_s1.matched_b.should == correct_lcs
    end

    it "should have the correct skipped sequences for the left sequence" do
      @callback_s1_s2.discards_a.should == skipped_seq1
      @callback_s2_s1.discards_a.should == skipped_seq2
    end

    it "should have the correct skipped sequences for the right sequence" do
      @callback_s1_s2.discards_b.should == skipped_seq2
      @callback_s2_s1.discards_b.should == skipped_seq1
    end

    it "should have done markers differently-sized sequences" do
      @callback_s1_s2.done_a.should == [[ "p", 9, "s", 10 ]]
      @callback_s1_s2.done_b.should be_empty

      # 20110731 I don't yet understand why this particular behaviour
      # isn't transitive.
      @callback_s2_s1.done_a.should be_empty
      @callback_s2_s1.done_b.should be_empty
    end
  end
end

# vim: ft=ruby
