require 'runtime/interval_skip_list/spec_helper'

describe "The palindromic fixture", :palindromic => true do
  include PalindromicFixtureSharedContext

  describe " #nodes" do
    describe "[0]" do
      before do
        @node = list.nodes[0]
      end

      it "has a key of 1 and a height of 3" do
        node.key.should == 1
        node.height.should == 3
      end

      it "has :c, :d, :e, and :f as its only forward markers at level 2" do
        node.forward_markers[2].should have_markers(:c, :d, :e, :f)
        end

      it "has  :a, :b as its only forward markers at level 1" do
        node.forward_markers[1].should have_markers(:a, :b)
      end

      it "has no forward markers at level 0" do
        node.forward_markers[0].should be_empty
      end

      it "has no markers" do
        node.markers.should be_empty
      end
    end

    describe "[1]" do
      before do
        @node = list.nodes[1]
      end

      it "has a key of 3 and a height of 2" do
        node.key.should == 3
        node.height.should == 2
      end

      it "has no forward markers at level 1" do
        node.forward_markers[1].should be_empty
      end

      it "has :b as its only forward marker at level 0" do
        node.forward_markers[0].should have_marker(:b)
      end

      it "has :a and :b as its only markers" do
        node.markers.should have_markers(:a, :b)
      end
    end

    describe "[2]" do
      before do
        @node = list.nodes[2]
      end

      it "has a key of 5 and a height of 1" do
        node.key.should == 5
        node.height.should == 1
      end

      it "has :g as its only forward marker at level 0" do
        node.forward_markers[0].should have_marker(:g)
      end

      it "has :b as its only marker" do
        node.markers.should have_marker(:b)
      end
    end

    describe "[3]" do
      before do
        @node = list.nodes[3]
      end

      it "has a key of 7 and a height of 3" do
        node.key.should == 7
        node.height.should == 3
      end

      it "has :f and :g as its only forward markers at level 2" do
        node.forward_markers[2].should have_markers(:f, :g)
      end

      it "has :e as its only forward markers at level 1" do
        node.forward_markers[1].should have_marker(:e)
      end

      it "has :d as its only forward marker at level 0" do
        node.forward_markers[0].should have_markers(:d)
      end

      it "has :c, :d, :e, :f and :g as its only markers" do
        node.markers.should have_markers(:c, :d, :e, :f, :g)
      end
    end

    describe "[4]" do
      before do
        @node = list.nodes[4]
      end

      it "has a key of 9 and a height of 1" do
        node.key.should == 9
        node.height.should == 1
      end

      it "has no forward markers at any level" do
        node.forward_markers[0].should be_empty
      end

      it "has :d as its only marker" do
        node.markers.should have_markers(:d)
      end
    end

    describe "[5]" do
      before do
        @node = list.nodes[5]
      end

      it "has a key of 11 and a height of 2" do
        node.key.should == 11
        node.height.should == 2
      end

      it "has no forward markers at any level" do
        node.forward_markers[0].should be_empty
        node.forward_markers[1].should be_empty
      end

      it "has :e as its only marker" do
        node.markers.should have_markers(:e)
      end
    end

    describe "[6]" do
      before do
        @node = list.nodes[6]
      end

      it "has a key of 13 and a height of 3" do
        node.key.should == 13
        node.height.should == 3
      end

      it "has no forward markers at any level" do
        node.forward_markers[0].should be_empty
        node.forward_markers[1].should be_empty
        node.forward_markers[2].should be_empty
      end

      it "has :f and :g as its only markers" do
        node.markers.should have_markers(:f, :g)
      end
    end
  end
end
