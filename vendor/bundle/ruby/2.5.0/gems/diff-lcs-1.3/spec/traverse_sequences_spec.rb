# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe "Diff::LCS.traverse_sequences" do
  describe "callback with no finishers" do
    describe "over (seq1, seq2)" do
      before(:each) do
        @callback_s1_s2 = simple_callback_no_finishers
        Diff::LCS.traverse_sequences(seq1, seq2, @callback_s1_s2)

        @callback_s2_s1 = simple_callback_no_finishers
        Diff::LCS.traverse_sequences(seq2, seq1, @callback_s2_s1)
      end

      it "has the correct LCS result on left-matches" do
        expect(@callback_s1_s2.matched_a).to eq(correct_lcs)
        expect(@callback_s2_s1.matched_a).to eq(correct_lcs)
      end

      it "has the correct LCS result on right-matches" do
        expect(@callback_s1_s2.matched_b).to eq(correct_lcs)
        expect(@callback_s2_s1.matched_b).to eq(correct_lcs)
      end

      it "has the correct skipped sequences with the left sequence" do
        expect(@callback_s1_s2.discards_a).to eq(skipped_seq1)
        expect(@callback_s2_s1.discards_a).to eq(skipped_seq2)
      end

      it "has the correct skipped sequences with the right sequence" do
        expect(@callback_s1_s2.discards_b).to eq(skipped_seq2)
        expect(@callback_s2_s1.discards_b).to eq(skipped_seq1)
      end

      it "does not have anything done markers from the left or right sequences" do
        expect(@callback_s1_s2.done_a).to be_empty
        expect(@callback_s1_s2.done_b).to be_empty
        expect(@callback_s2_s1.done_a).to be_empty
        expect(@callback_s2_s1.done_b).to be_empty
      end
    end

    describe "over (hello, hello)" do
      before(:each) do
        @callback = simple_callback_no_finishers
        Diff::LCS.traverse_sequences(hello, hello, @callback)
      end

      it "has the correct LCS result on left-matches" do
        expect(@callback.matched_a).to eq(hello.split(//))
      end

      it "has the correct LCS result on right-matches" do
        expect(@callback.matched_b).to eq(hello.split(//))
      end

      it "has the correct skipped sequences with the left sequence", :only => true do
        expect(@callback.discards_a).to be_empty
      end

      it "has the correct skipped sequences with the right sequence" do
        expect(@callback.discards_b).to be_empty
      end

      it "does not have anything done markers from the left or right sequences" do
        expect(@callback.done_a).to be_empty
        expect(@callback.done_b).to be_empty
      end
    end

    describe "over (hello_ary, hello_ary)" do
      before(:each) do
        @callback = simple_callback_no_finishers
        Diff::LCS.traverse_sequences(hello_ary, hello_ary, @callback)
      end

      it "has the correct LCS result on left-matches" do
        expect(@callback.matched_a).to eq(hello_ary)
      end

      it "has the correct LCS result on right-matches" do
        expect(@callback.matched_b).to eq(hello_ary)
      end

      it "has the correct skipped sequences with the left sequence" do
        expect(@callback.discards_a).to be_empty
      end

      it "has the correct skipped sequences with the right sequence" do
        expect(@callback.discards_b).to be_empty
      end

      it "does not have anything done markers from the left or right sequences" do
        expect(@callback.done_a).to be_empty
        expect(@callback.done_b).to be_empty
      end
    end
  end

  describe "callback with finisher" do
    before(:each) do
      @callback_s1_s2 = simple_callback
      Diff::LCS.traverse_sequences(seq1, seq2, @callback_s1_s2)
      @callback_s2_s1 = simple_callback
      Diff::LCS.traverse_sequences(seq2, seq1, @callback_s2_s1)
    end

    it "has the correct LCS result on left-matches" do
      expect(@callback_s1_s2.matched_a).to eq(correct_lcs)
      expect(@callback_s2_s1.matched_a).to eq(correct_lcs)
    end

    it "has the correct LCS result on right-matches" do
      expect(@callback_s1_s2.matched_b).to eq(correct_lcs)
      expect(@callback_s2_s1.matched_b).to eq(correct_lcs)
    end

    it "has the correct skipped sequences for the left sequence" do
      expect(@callback_s1_s2.discards_a).to eq(skipped_seq1)
      expect(@callback_s2_s1.discards_a).to eq(skipped_seq2)
    end

    it "has the correct skipped sequences for the right sequence" do
      expect(@callback_s1_s2.discards_b).to eq(skipped_seq2)
      expect(@callback_s2_s1.discards_b).to eq(skipped_seq1)
    end

    it "has done markers differently-sized sequences" do
      expect(@callback_s1_s2.done_a).to eq([[ "p", 9, "s", 10 ]])
      expect(@callback_s1_s2.done_b).to be_empty

      # 20110731 I don't yet understand why this particular behaviour
      # isn't transitive.
      expect(@callback_s2_s1.done_a).to be_empty
      expect(@callback_s2_s1.done_b).to be_empty
    end
  end
end
