# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe "Diff::LCS.sdiff" do
  include Diff::LCS::SpecHelper::Matchers

  shared_examples "compare sequences correctly" do
    it "compares s1 -> s2 correctly" do
      expect(Diff::LCS.sdiff(s1, s2)).to eq(context_diff(result))
    end

    it "compares s2 -> s1 correctly" do
      expect(Diff::LCS.sdiff(s2, s1)).to eq(context_diff(reverse_sdiff(result)))
    end
  end

  describe "using seq1 & seq2" do
    let(:s1) { seq1 }
    let(:s2) { seq2 }
    let(:result) { correct_forward_sdiff }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(abc def yyy xxx ghi jkl) & %w(abc dxf xxx ghi jkl)" do
    let(:s1) { %w(abc def yyy xxx ghi jkl) }
    let(:s2) { %w(abc dxf xxx ghi jkl) }
    let(:result) {
      [
        [ '=', [ 0, 'abc' ], [ 0, 'abc' ] ],
        [ '!', [ 1, 'def' ], [ 1, 'dxf' ] ],
        [ '-', [ 2, 'yyy' ], [ 2,  nil  ] ],
        [ '=', [ 3, 'xxx' ], [ 2, 'xxx' ] ],
        [ '=', [ 4, 'ghi' ], [ 3, 'ghi' ] ],
        [ '=', [ 5, 'jkl' ], [ 4, 'jkl' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(a b c d e) & %w(a e)" do
    let(:s1) { %w(a b c d e) }
    let(:s2) { %w(a e) }
    let(:result) {
      [
        [ '=', [ 0, 'a' ], [ 0, 'a' ] ],
        [ '-', [ 1, 'b' ], [ 1, nil ] ],
        [ '-', [ 2, 'c' ], [ 1, nil ] ],
        [ '-', [ 3, 'd' ], [ 1, nil ] ],
        [ '=', [ 4, 'e' ], [ 1, 'e' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(a e) & %w(a b c d e)" do
    let(:s1) { %w(a e) }
    let(:s2) { %w(a b c d e) }
    let(:result) {
      [
        [ '=', [ 0, 'a' ], [ 0, 'a' ] ],
        [ '+', [ 1, nil ], [ 1, 'b' ] ],
        [ '+', [ 1, nil ], [ 2, 'c' ] ],
        [ '+', [ 1, nil ], [ 3, 'd' ] ],
        [ '=', [ 1, 'e' ], [ 4, 'e' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(v x a e) & %w(w y a b c d e)" do
    let(:s1) { %w(v x a e) }
    let(:s2) { %w(w y a b c d e) }
    let(:result) {
      [
        [ '!', [ 0, 'v' ], [ 0, 'w' ] ],
        [ '!', [ 1, 'x' ], [ 1, 'y' ] ],
        [ '=', [ 2, 'a' ], [ 2, 'a' ] ],
        [ '+', [ 3, nil ], [ 3, 'b' ] ],
        [ '+', [ 3, nil ], [ 4, 'c' ] ],
        [ '+', [ 3, nil ], [ 5, 'd' ] ],
        [ '=', [ 3, 'e' ], [ 6, 'e' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(x a e) & %w(a b c d e)" do
    let(:s1) { %w(x a e) }
    let(:s2) { %w(a b c d e) }
    let(:result) {
      [
        [ '-', [ 0, 'x' ], [ 0, nil ] ],
        [ '=', [ 1, 'a' ], [ 0, 'a' ] ],
        [ '+', [ 2, nil ], [ 1, 'b' ] ],
        [ '+', [ 2, nil ], [ 2, 'c' ] ],
        [ '+', [ 2, nil ], [ 3, 'd' ] ],
        [ '=', [ 2, 'e' ], [ 4, 'e' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(a e) & %w(x a b c d e)" do
    let(:s1) { %w(a e) }
    let(:s2) { %w(x a b c d e) }
    let(:result) {
      [
        [ '+', [ 0, nil ], [ 0, 'x' ] ],
        [ '=', [ 0, 'a' ], [ 1, 'a' ] ],
        [ '+', [ 1, nil ], [ 2, 'b' ] ],
        [ '+', [ 1, nil ], [ 3, 'c' ] ],
        [ '+', [ 1, nil ], [ 4, 'd' ] ],
        [ '=', [ 1, 'e' ], [ 5, 'e' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(a e v) & %w(x a b c d e w x)" do
    let(:s1) { %w(a e v) }
    let(:s2) { %w(x a b c d e w x) }
    let(:result) {
      [
        [ '+', [ 0, nil ], [ 0, 'x' ] ],
        [ '=', [ 0, 'a' ], [ 1, 'a' ] ],
        [ '+', [ 1, nil ], [ 2, 'b' ] ],
        [ '+', [ 1, nil ], [ 3, 'c' ] ],
        [ '+', [ 1, nil ], [ 4, 'd' ] ],
        [ '=', [ 1, 'e' ], [ 5, 'e' ] ],
        [ '!', [ 2, 'v' ], [ 6, 'w' ] ],
        [ '+', [ 3, nil ], [ 7, 'x' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w() & %w(a b c)" do
    let(:s1) { %w() }
    let(:s2) { %w(a b c) }
    let(:result) {
      [
        [ '+', [ 0, nil ], [ 0, 'a' ] ],
        [ '+', [ 0, nil ], [ 1, 'b' ] ],
        [ '+', [ 0, nil ], [ 2, 'c' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(a b c) & %w(1)" do
    let(:s1) { %w(a b c) }
    let(:s2) { %w(1) }
    let(:result) {
      [
        [ '!', [ 0, 'a' ], [ 0, '1' ] ],
        [ '-', [ 1, 'b' ], [ 1, nil ] ],
        [ '-', [ 2, 'c' ], [ 1, nil ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(a b c) & %w(c)" do
    let(:s1) { %w(a b c) }
    let(:s2) { %w(c) }
    let(:result) {
      [
        [ '-', [ 0, 'a' ], [ 0, nil ] ],
        [ '-', [ 1, 'b' ], [ 0, nil ] ],
        [ '=', [ 2, 'c' ], [ 0, 'c' ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using %w(abcd efgh ijkl mnop) & []" do
    let(:s1) { %w(abcd efgh ijkl mnop) }
    let(:s2) { [] }
    let(:result) {
      [
        [ '-', [ 0, 'abcd' ], [ 0, nil ] ],
        [ '-', [ 1, 'efgh' ], [ 0, nil ] ],
        [ '-', [ 2, 'ijkl' ], [ 0, nil ] ],
        [ '-', [ 3, 'mnop' ], [ 0, nil ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end

  describe "using [[1,2]] & []" do
    let(:s1) { [ [ 1, 2 ] ] }
    let(:s2) { [] }
    let(:result) {
      [
        [ '-', [ 0, [ 1, 2 ] ], [ 0, nil ] ]
      ]
    }

    it_has_behavior "compare sequences correctly"
  end
end
