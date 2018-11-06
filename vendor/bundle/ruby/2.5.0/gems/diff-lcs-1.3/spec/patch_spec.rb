# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe "Diff::LCS.patch" do
  include Diff::LCS::SpecHelper::Matchers

  shared_examples "patch sequences correctly" do
    it "correctly patches left-to-right (patch autodiscovery)" do
      expect(Diff::LCS.patch(s1, patch_set)).to eq(s2)
    end

    it "correctly patches left-to-right (explicit patch)" do
      expect(Diff::LCS.patch(s1, patch_set, :patch)).to eq(s2)
      expect(Diff::LCS.patch!(s1, patch_set)).to eq(s2)
    end

    it "correctly patches right-to-left (unpatch autodiscovery)" do
      expect(Diff::LCS.patch(s2, patch_set)).to eq(s1)
    end

    it "correctly patches right-to-left (explicit unpatch)" do
      expect(Diff::LCS.patch(s2, patch_set, :unpatch)).to eq(s1)
      expect(Diff::LCS.unpatch!(s2, patch_set)).to eq(s1)
    end
  end

  describe "using a Diff::LCS.diff patchset" do
    describe "an empty patchset returns the source" do
      it "works on a string (hello)" do
        diff = Diff::LCS.diff(hello, hello)
        expect(Diff::LCS::patch(hello, diff)).to eq(hello)
      end

      it "works on an array %W(h e l l o)" do
        diff = Diff::LCS.diff(hello_ary, hello_ary)
        expect(Diff::LCS::patch(hello_ary, diff)).to eq(hello_ary)
      end
    end

    describe "with default diff callbacks (DiffCallbacks)" do
      describe "forward (s1 -> s2)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq1 }
          let(:s2) { seq2 }
          let(:patch_set) { Diff::LCS.diff(seq1, seq2) }
        end
      end

      describe "reverse (s2 -> s1)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq2 }
          let(:s2) { seq1 }
          let(:patch_set) { Diff::LCS.diff(seq2, seq1) }
        end
      end
    end

    describe "with context diff callbacks (ContextDiffCallbacks)" do
      describe "forward (s1 -> s2)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq1 }
          let(:s2) { seq2 }
          let(:patch_set) {
            Diff::LCS.diff(seq1, seq2, Diff::LCS::ContextDiffCallbacks)
          }
        end
      end

      describe "reverse (s2 -> s1)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq2 }
          let(:s2) { seq1 }
          let(:patch_set) {
            Diff::LCS.diff(seq2, seq1, Diff::LCS::ContextDiffCallbacks)
          }
        end
      end
    end

    describe "with sdiff callbacks (SDiffCallbacks)" do
      describe "forward (s1 -> s2)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq1 }
          let(:s2) { seq2 }
          let(:patch_set) {
            Diff::LCS.diff(seq1, seq2, Diff::LCS::SDiffCallbacks)
          }
        end
      end

      describe "reverse (s2 -> s1)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq2 }
          let(:s2) { seq1 }
          let(:patch_set) {
            Diff::LCS.diff(seq2, seq1, Diff::LCS::SDiffCallbacks)
          }
        end
      end
    end
  end

  describe "using a Diff::LCS.sdiff patchset" do
    describe "an empty patchset returns the source" do
      it "works on a string (hello)" do
        expect(Diff::LCS::patch(hello, Diff::LCS.sdiff(hello, hello))).to eq(hello)
      end

      it "works on an array %W(h e l l o)" do
        expect(Diff::LCS::patch(hello_ary, Diff::LCS.sdiff(hello_ary, hello_ary))).to eq(hello_ary)
      end
    end

    describe "with default diff callbacks (DiffCallbacks)" do
      describe "forward (s1 -> s2)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq1 }
          let(:s2) { seq2 }
          let(:patch_set) {
            Diff::LCS.sdiff(seq1, seq2, Diff::LCS::DiffCallbacks)
          }
        end
      end

      describe "reverse (s2 -> s1)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq2 }
          let(:s2) { seq1 }
          let(:patch_set) {
            Diff::LCS.sdiff(seq2, seq1, Diff::LCS::DiffCallbacks)
          }
        end
      end
    end

    describe "with context diff callbacks (DiffCallbacks)" do
      describe "forward (s1 -> s2)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq1 }
          let(:s2) { seq2 }
          let(:patch_set) {
            Diff::LCS.sdiff(seq1, seq2, Diff::LCS::ContextDiffCallbacks)
          }
        end
      end

      describe "reverse (s2 -> s1)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq2 }
          let(:s2) { seq1 }
          let(:patch_set) {
            Diff::LCS.sdiff(seq2, seq1, Diff::LCS::ContextDiffCallbacks)
          }
        end
      end
    end

    describe "with sdiff callbacks (SDiffCallbacks)" do
      describe "forward (s1 -> s2)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq1 }
          let(:s2) { seq2 }
          let(:patch_set) { Diff::LCS.sdiff(seq1, seq2) }
        end
      end

      describe "reverse (s2 -> s1)" do
        it_has_behavior "patch sequences correctly" do
          let(:s1) { seq2 }
          let(:s2) { seq1 }
          let(:patch_set) { Diff::LCS.sdiff(seq2, seq1) }
        end
      end
    end
  end

  # Note: because of the error in autodiscovery ("does not autodiscover s1
  # to s2 patches"), this cannot use the "patch sequences correctly" shared
  # set. Once the bug in autodiscovery is fixed, this can be converted as
  # above.
  describe "fix bug 891: patchsets do not contain the last equal part" do
    before :each do
      @s1 = %w(a b c d   e f g h i j k)
      @s2 = %w(a b c d D e f g h i j k)
    end

    describe "using Diff::LCS.diff with default diff callbacks" do
      before :each do
        @patch_set_s1_s2 = Diff::LCS.diff(@s1, @s2)
        @patch_set_s2_s1 = Diff::LCS.diff(@s2, @s1)
      end

      it "autodiscovers s1 to s2 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s1_s2)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s2_s1)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 the left-to-right patches" do
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1)).to eq(@s1)
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2)).to eq(@s1)
      end

      it "correctly patches left-to-right (explicit patch)" do
        expect(Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch)).to eq(@s2)
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch)).to eq(@s1)
        expect(Diff::LCS.patch!(@s1, @patch_set_s1_s2)).to eq(@s2)
        expect(Diff::LCS.patch!(@s2, @patch_set_s2_s1)).to eq(@s1)
      end

      it "correctly patches right-to-left (explicit unpatch)" do
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch)).to eq(@s1)
        expect(Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch)).to eq(@s2)
        expect(Diff::LCS.unpatch!(@s2, @patch_set_s1_s2)).to eq(@s1)
        expect(Diff::LCS.unpatch!(@s1, @patch_set_s2_s1)).to eq(@s2)
      end
    end

    describe "using Diff::LCS.diff with context diff callbacks" do
      before :each do
        @patch_set_s1_s2 = Diff::LCS.diff(@s1, @s2,
                                          Diff::LCS::ContextDiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.diff(@s2, @s1,
                                          Diff::LCS::ContextDiffCallbacks)
      end

      it "autodiscovers s1 to s2 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s1_s2)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s2_s1)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 the left-to-right patches" do
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1)).to eq(@s1)
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2)).to eq(@s1)
      end

      it "correctly patches left-to-right (explicit patch)" do
        expect(Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch)).to eq(@s2)
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch)).to eq(@s1)
        expect(Diff::LCS.patch!(@s1, @patch_set_s1_s2)).to eq(@s2)
        expect(Diff::LCS.patch!(@s2, @patch_set_s2_s1)).to eq(@s1)
      end

      it "correctly patches right-to-left (explicit unpatch)" do
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch)).to eq(@s1)
        expect(Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch)).to eq(@s2)
        expect(Diff::LCS.unpatch!(@s2, @patch_set_s1_s2)).to eq(@s1)
        expect(Diff::LCS.unpatch!(@s1, @patch_set_s2_s1)).to eq(@s2)
      end
    end

    describe "using Diff::LCS.diff with sdiff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.diff(@s1, @s2,
                                          Diff::LCS::SDiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.diff(@s2, @s1,
                                          Diff::LCS::SDiffCallbacks)
      end

      it "autodiscovers s1 to s2 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s1_s2)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s2_s1)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 the left-to-right patches" do
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1)).to eq(@s1)
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2)).to eq(@s1)
      end

      it "correctly patches left-to-right (explicit patch)" do
        expect(Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch)).to eq(@s2)
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch)).to eq(@s1)
        expect(Diff::LCS.patch!(@s1, @patch_set_s1_s2)).to eq(@s2)
        expect(Diff::LCS.patch!(@s2, @patch_set_s2_s1)).to eq(@s1)
      end

      it "correctly patches right-to-left (explicit unpatch)" do
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch)).to eq(@s1)
        expect(Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch)).to eq(@s2)
        expect(Diff::LCS.unpatch!(@s2, @patch_set_s1_s2)).to eq(@s1)
        expect(Diff::LCS.unpatch!(@s1, @patch_set_s2_s1)).to eq(@s2)
      end
    end

    describe "using Diff::LCS.sdiff with default sdiff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.sdiff(@s1, @s2)
        @patch_set_s2_s1 = Diff::LCS.sdiff(@s2, @s1)
      end

      it "autodiscovers s1 to s2 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s1_s2)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s2_s1)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 the left-to-right patches" do
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1)).to eq(@s1)
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2)).to eq(@s1)
      end

      it "correctly patches left-to-right (explicit patch)" do
        expect(Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch)).to eq(@s2)
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch)).to eq(@s1)
        expect(Diff::LCS.patch!(@s1, @patch_set_s1_s2)).to eq(@s2)
        expect(Diff::LCS.patch!(@s2, @patch_set_s2_s1)).to eq(@s1)
      end

      it "correctly patches right-to-left (explicit unpatch)" do
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch)).to eq(@s1)
        expect(Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch)).to eq(@s2)
        expect(Diff::LCS.unpatch!(@s2, @patch_set_s1_s2)).to eq(@s1)
        expect(Diff::LCS.unpatch!(@s1, @patch_set_s2_s1)).to eq(@s2)
      end
    end

    describe "using Diff::LCS.sdiff with context diff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.sdiff(@s1, @s2,
                                           Diff::LCS::ContextDiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.sdiff(@s2, @s1,
                                           Diff::LCS::ContextDiffCallbacks)
      end

      it "autodiscovers s1 to s2 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s1_s2)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s2_s1)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 the left-to-right patches" do
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1)).to eq(@s1)
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2)).to eq(@s1)
      end

      it "correctly patches left-to-right (explicit patch)" do
        expect(Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch)).to eq(@s2)
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch)).to eq(@s1)
        expect(Diff::LCS.patch!(@s1, @patch_set_s1_s2)).to eq(@s2)
        expect(Diff::LCS.patch!(@s2, @patch_set_s2_s1)).to eq(@s1)
      end

      it "correctly patches right-to-left (explicit unpatch)" do
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch)).to eq(@s1)
        expect(Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch)).to eq(@s2)
        expect(Diff::LCS.unpatch!(@s2, @patch_set_s1_s2)).to eq(@s1)
        expect(Diff::LCS.unpatch!(@s1, @patch_set_s2_s1)).to eq(@s2)
      end
    end

    describe "using Diff::LCS.sdiff with default diff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.sdiff(@s1, @s2, Diff::LCS::DiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.sdiff(@s2, @s1, Diff::LCS::DiffCallbacks)
      end

      it "autodiscovers s1 to s2 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s1_s2)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 patches" do
        expect do
          expect(Diff::LCS.patch(@s1, @patch_set_s2_s1)).to eq(@s2)
        end.to_not raise_error
      end

      it "autodiscovers s2 to s1 the left-to-right patches" do
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1)).to eq(@s1)
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2)).to eq(@s1)
      end

      it "correctly patches left-to-right (explicit patch)" do
        expect(Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch)).to eq(@s2)
        expect(Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch)).to eq(@s1)
        expect(Diff::LCS.patch!(@s1, @patch_set_s1_s2)).to eq(@s2)
        expect(Diff::LCS.patch!(@s2, @patch_set_s2_s1)).to eq(@s1)
      end

      it "correctly patches right-to-left (explicit unpatch)" do
        expect(Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch)).to eq(@s1)
        expect(Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch)).to eq(@s2)
        expect(Diff::LCS.unpatch!(@s2, @patch_set_s1_s2)).to eq(@s1)
        expect(Diff::LCS.unpatch!(@s1, @patch_set_s2_s1)).to eq(@s2)
      end
    end
  end
end
