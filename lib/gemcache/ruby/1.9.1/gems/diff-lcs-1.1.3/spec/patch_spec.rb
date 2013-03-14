# -*- ruby encoding: utf-8 -*-

require 'spec_helper'

describe "Diff::LCS.patch" do
  include Diff::LCS::SpecHelper::Matchers

  shared_examples "patch sequences correctly" do
    it "should correctly patch left-to-right (patch autodiscovery)" do
      Diff::LCS.patch(s1, patch_set).should == s2
    end

    it "should correctly patch left-to-right (explicit patch)" do
      Diff::LCS.patch(s1, patch_set, :patch).should == s2
      Diff::LCS.patch!(s1, patch_set).should == s2
    end

    it "should correctly patch right-to-left (unpatch autodiscovery)" do
      Diff::LCS.patch(s2, patch_set).should == s1
    end

    it "should correctly patch right-to-left (explicit unpatch)" do
      Diff::LCS.patch(s2, patch_set, :unpatch).should == s1
      Diff::LCS.unpatch!(s2, patch_set).should == s1
    end
  end

  describe "using a Diff::LCS.diff patchset" do
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
    before(:each) do
      @s1 = %w(a b c d   e f g h i j k)
      @s2 = %w(a b c d D e f g h i j k)
    end

    describe "using Diff::LCS.diff with default diff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.diff(@s1, @s2)
        @patch_set_s2_s1 = Diff::LCS.diff(@s2, @s1)
      end

      it "does not autodiscover s1 to s2 patches" do
        # It should, but it doesn't.
        expect do
          Diff::LCS.patch(@s1, @patch_set_s1_s2).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)

        expect do
          Diff::LCS.patch(@s1, @patch_set_s2_s1).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)
      end

      it "should autodiscover s2 to s1 the left-to-right patches" do
        Diff::LCS.patch(@s2, @patch_set_s2_s1).should == @s1
        Diff::LCS.patch(@s2, @patch_set_s1_s2).should == @s1
      end

      it "should correctly patch left-to-right (explicit patch)" do
        Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch).should == @s2
        Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch).should == @s1
        Diff::LCS.patch!(@s1, @patch_set_s1_s2).should == @s2
        Diff::LCS.patch!(@s2, @patch_set_s2_s1).should == @s1
      end

      it "should correctly patch right-to-left (explicit unpatch)" do
        Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch).should == @s1
        Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch).should == @s2
        Diff::LCS.unpatch!(@s2, @patch_set_s1_s2).should == @s1
        Diff::LCS.unpatch!(@s1, @patch_set_s2_s1).should == @s2
      end
    end

    describe "using Diff::LCS.diff with context diff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.diff(@s1, @s2, Diff::LCS::ContextDiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.diff(@s2, @s1, Diff::LCS::ContextDiffCallbacks)
      end

      it "does not autodiscover s1 to s2 patches" do
        # It should, but it doesn't.
        expect do
          Diff::LCS.patch(@s1, @patch_set_s1_s2).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)

        expect do
          Diff::LCS.patch(@s1, @patch_set_s2_s1).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)
      end

      it "should autodiscover s2 to s1 the left-to-right patches" do
        Diff::LCS.patch(@s2, @patch_set_s2_s1).should == @s1
        Diff::LCS.patch(@s2, @patch_set_s1_s2).should == @s1
      end

      it "should correctly patch left-to-right (explicit patch)" do
        Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch).should == @s2
        Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch).should == @s1
        Diff::LCS.patch!(@s1, @patch_set_s1_s2).should == @s2
        Diff::LCS.patch!(@s2, @patch_set_s2_s1).should == @s1
      end

      it "should correctly patch right-to-left (explicit unpatch)" do
        Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch).should == @s1
        Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch).should == @s2
        Diff::LCS.unpatch!(@s2, @patch_set_s1_s2).should == @s1
        Diff::LCS.unpatch!(@s1, @patch_set_s2_s1).should == @s2
      end
    end

    describe "using Diff::LCS.diff with sdiff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.diff(@s1, @s2, Diff::LCS::SDiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.diff(@s2, @s1, Diff::LCS::SDiffCallbacks)
      end

      it "does not autodiscover s1 to s2 patches" do
        # It should, but it doesn't.
        expect do
          Diff::LCS.patch(@s1, @patch_set_s1_s2).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)

        expect do
          Diff::LCS.patch(@s1, @patch_set_s2_s1).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)
      end

      it "should autodiscover s2 to s1 the left-to-right patches" do
        Diff::LCS.patch(@s2, @patch_set_s2_s1).should == @s1
        Diff::LCS.patch(@s2, @patch_set_s1_s2).should == @s1
      end

      it "should correctly patch left-to-right (explicit patch)" do
        Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch).should == @s2
        Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch).should == @s1
        Diff::LCS.patch!(@s1, @patch_set_s1_s2).should == @s2
        Diff::LCS.patch!(@s2, @patch_set_s2_s1).should == @s1
      end

      it "should correctly patch right-to-left (explicit unpatch)" do
        Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch).should == @s1
        Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch).should == @s2
        Diff::LCS.unpatch!(@s2, @patch_set_s1_s2).should == @s1
        Diff::LCS.unpatch!(@s1, @patch_set_s2_s1).should == @s2
      end
    end

    describe "using Diff::LCS.sdiff with default sdiff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.sdiff(@s1, @s2)
        @patch_set_s2_s1 = Diff::LCS.sdiff(@s2, @s1)
      end

      it "does not autodiscover s1 to s2 patches" do
        # It should, but it doesn't.
        expect do
          Diff::LCS.patch(@s1, @patch_set_s1_s2).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)

        expect do
          Diff::LCS.patch(@s1, @patch_set_s2_s1).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)
      end

      it "should autodiscover s2 to s1 the left-to-right patches" do
        Diff::LCS.patch(@s2, @patch_set_s2_s1).should == @s1
        Diff::LCS.patch(@s2, @patch_set_s1_s2).should == @s1
      end

      it "should correctly patch left-to-right (explicit patch)" do
        Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch).should == @s2
        Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch).should == @s1
        Diff::LCS.patch!(@s1, @patch_set_s1_s2).should == @s2
        Diff::LCS.patch!(@s2, @patch_set_s2_s1).should == @s1
      end

      it "should correctly patch right-to-left (explicit unpatch)" do
        Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch).should == @s1
        Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch).should == @s2
        Diff::LCS.unpatch!(@s2, @patch_set_s1_s2).should == @s1
        Diff::LCS.unpatch!(@s1, @patch_set_s2_s1).should == @s2
      end
    end

    describe "using Diff::LCS.sdiff with context diff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.sdiff(@s1, @s2, Diff::LCS::ContextDiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.sdiff(@s2, @s1, Diff::LCS::ContextDiffCallbacks)
      end

      it "does not autodiscover s1 to s2 patches" do
        # It should, but it doesn't.
        expect do
          Diff::LCS.patch(@s1, @patch_set_s1_s2).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)

        expect do
          Diff::LCS.patch(@s1, @patch_set_s2_s1).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)
      end

      it "should autodiscover s2 to s1 the left-to-right patches" do
        Diff::LCS.patch(@s2, @patch_set_s2_s1).should == @s1
        Diff::LCS.patch(@s2, @patch_set_s1_s2).should == @s1
      end

      it "should correctly patch left-to-right (explicit patch)" do
        Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch).should == @s2
        Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch).should == @s1
        Diff::LCS.patch!(@s1, @patch_set_s1_s2).should == @s2
        Diff::LCS.patch!(@s2, @patch_set_s2_s1).should == @s1
      end

      it "should correctly patch right-to-left (explicit unpatch)" do
        Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch).should == @s1
        Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch).should == @s2
        Diff::LCS.unpatch!(@s2, @patch_set_s1_s2).should == @s1
        Diff::LCS.unpatch!(@s1, @patch_set_s2_s1).should == @s2
      end
    end

    describe "using Diff::LCS.sdiff with default diff callbacks" do
      before(:each) do
        @patch_set_s1_s2 = Diff::LCS.sdiff(@s1, @s2, Diff::LCS::DiffCallbacks)
        @patch_set_s2_s1 = Diff::LCS.sdiff(@s2, @s1, Diff::LCS::DiffCallbacks)
      end

      it "does not autodiscover s1 to s2 patches" do
        # It should, but it doesn't.
        expect do
          Diff::LCS.patch(@s1, @patch_set_s1_s2).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)

        expect do
          Diff::LCS.patch(@s1, @patch_set_s2_s1).should == @s2
        end.to raise_error(RuntimeError, /provided patchset/)
      end

      it "should autodiscover s2 to s1 the left-to-right patches" do
        Diff::LCS.patch(@s2, @patch_set_s2_s1).should == @s1
        Diff::LCS.patch(@s2, @patch_set_s1_s2).should == @s1
      end

      it "should correctly patch left-to-right (explicit patch)" do
        Diff::LCS.patch(@s1, @patch_set_s1_s2, :patch).should == @s2
        Diff::LCS.patch(@s2, @patch_set_s2_s1, :patch).should == @s1
        Diff::LCS.patch!(@s1, @patch_set_s1_s2).should == @s2
        Diff::LCS.patch!(@s2, @patch_set_s2_s1).should == @s1
      end

      it "should correctly patch right-to-left (explicit unpatch)" do
        Diff::LCS.patch(@s2, @patch_set_s1_s2, :unpatch).should == @s1
        Diff::LCS.patch(@s1, @patch_set_s2_s1, :unpatch).should == @s2
        Diff::LCS.unpatch!(@s2, @patch_set_s1_s2).should == @s1
        Diff::LCS.unpatch!(@s1, @patch_set_s2_s1).should == @s2
      end
    end
  end
end

# vim: ft=ruby
