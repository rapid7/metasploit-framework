require 'runtime/interval_skip_list/spec_helper'

describe IntervalSkipList, :palindromic => true do
  include PalindromicFixtureSharedContext

  describe "#overlapping" do
    it "returns intervals :d, :e, :f, and :g for 7..9" do
      list.overlapping(7..9)[0].should have_markers(:d, :e, :f, :g)
    end

    it "returns intervals :b, :c, :d, :e, :f, and :g for 3..7" do
      list.overlapping(3..7)[0].should have_markers(:b, :c, :d, :e, :f, :g )
    end

    it "returns intervals :b, :c, :d, :e, :f, and :g for 3..6" do
      list.overlapping(3..6)[0].should have_markers(:b, :c, :d, :e, :f, :g )
    end

    describe ", when :x is inserted on 3..7" do
      before do
        list.insert(3..7, :x)
      end

      it "returns intervals :b, :c, :d, :e, :f, :x for 3..5" do
        list.overlapping(3..5)[0].should have_markers(:b, :c, :d, :e, :f, :x)
      end
    end
  end


  describe "when 7..7 is expired with a length change of 0" do
    before do
      list.expire(7..7, 0)
    end

    describe " #nodes" do
      attr_reader :nodes, :node

      before do
        @nodes = list.nodes
      end

      it "has a size of 4" do
        nodes.size.should == 4
      end

      describe "[0]" do
        before do
          @node = nodes[0]
        end

        it "has a key of 1 and a height of 3" do
          node.key.should == 1
          node.height.should == 3
        end

        it "has no forward markers at level 0" do
          node.forward_markers[0].should be_empty
        end

        it "has :a and :b as its only forward markers on level 1" do
          node.forward_markers[1].should have_markers(:a, :b)
        end

        it "has :c as its only forward marker on level 2" do
          node.forward_markers[2].should have_markers(:c)
        end

        it "has no markers" do
          node.markers.should be_empty
        end
      end

      describe "[1]" do
        before do
          @node = nodes[1]
        end

        it "has a key of 3 and a height of 2" do
          node.key.should == 3
          node.height.should == 2
        end

        it "has :b as its only forward marker on level 0" do
          node.forward_markers[0].should have_markers(:b)
        end

        it "has no forward markers on level 1" do
          node.forward_markers[1].should be_empty
        end

        it "has :a and :b as its only markers" do
          node.markers.should have_markers(:a, :b)
        end
      end

      describe "[2]" do
        before do
          @node = nodes[2]
        end

        it "has a key of 5 and a height of 1" do
          node.key.should == 5
          node.height.should == 1
        end

        it "has no forward markers on level 0" do
          node.forward_markers[0].should be_empty
        end

        it "has :b as its only marker" do
          node.markers.should have_markers(:b)
        end
      end

      describe "[3]" do
        before do
          @node = nodes[3]
        end

        it "has a key of 7 and a height of 3" do
          node.key.should == 7
          node.height.should == 3
        end

        it "has no forward markers at any level" do
          node.forward_markers[0].should be_empty
          node.forward_markers[1].should be_empty
          node.forward_markers[2].should be_empty
        end

        it "has :c as its only marker" do
          node.markers.should have_markers(:c)
        end
      end
    end
  end

  describe "when 4..4 is expired with a length change of 2" do
    before do
      list.expire(4..4, 2)
    end

    describe " #nodes" do
      attr_reader :nodes, :node

      before do
        @nodes = list.nodes
      end

      it "has a size of 4" do
        nodes.size.should == 4
      end

      describe "[0]" do
        before do
          @node = nodes[0]
        end

        it "has a key of 1 and a height of 3" do
          node.key.should == 1
          node.height.should == 3
        end

        it "has no forward markers at level 0 and 2" do
          node.forward_markers[0].should be_empty
          node.forward_markers[2].should be_empty
        end

        it "has :a as its only forward marker on level 1" do
          node.forward_markers[1].should have_markers(:a)
        end

        it "has no markers" do
          node.markers.should be_empty
        end
      end

      describe "[1]" do
        before do
          @node = nodes[1]
        end

        it "has a key of 3 and a height of 2" do
          node.key.should == 3
          node.height.should == 2
        end

        it "has no forward markers at any level" do
          node.forward_markers[0].should be_empty
          node.forward_markers[1].should be_empty
        end

        it "has :a as its only marker" do
          node.markers.should have_markers(:a)
        end
      end

      describe "[2]" do
        before do
          @node = nodes[2]
        end

        it "has a key of 7 and a height of 1" do
          node.key.should == 7
          node.height.should == 1
        end

        it "has :g as its only forward marker at level 0" do
          node.forward_markers[0].should have_markers(:g)
        end

        it "has no markers" do
          node.markers.should be_empty
        end
      end

      describe "[3]" do
        before do
          @node = nodes[3]
        end

        it "has a key of 15 and a height of 3" do
          node.key.should == 15
          node.height.should == 3
        end

        it "has no forward markers at any level" do
          node.forward_markers[0].should be_empty
          node.forward_markers[1].should be_empty
          node.forward_markers[2].should be_empty
        end

        it "has :g as its only marker" do
          node.markers.should have_markers(:g)
        end
      end
    end
  end

  describe "when :x is inserted on 1..5, :y on 7..11, and :z on 9..13" do
    before do
      list.insert(1..5, :x)
      list.insert(7..11, :y)
      list.insert(9..13, :z)
    end

    describe "when 4..8 is expired with a length change of -3" do
      before do
        list.expire(4..8, -3)
      end

      describe "#nodes" do
        attr_reader :nodes, :node
        before do
          @nodes = list.nodes
        end

        it "has a size of 4" do
          nodes.size.should == 4
        end

        describe "[0]" do
          before do
            @node = nodes[0]
          end

          it "has a key of 1 and height of 3" do
            node.key.should == 1
            node.height.should == 3
          end

          it "has :a as its only forward marker on level 1" do
            node.forward_markers[1].should have_markers(:a)
          end

          it "has no forward markers at level 0 and 2" do
            node.forward_markers[0].should be_empty
            node.forward_markers[2].should be_empty
          end

          it "has no markers" do
            node.markers.should be_empty
          end
        end

        describe "[1]" do
          before do
            @node = nodes[1]
          end

          it "has a key of 3 and height of 2" do
            node.key.should == 3
            node.height.should == 2
          end

          it "has no forward markers" do
            node.forward_markers[0].should be_empty
            node.forward_markers[1].should be_empty
          end

          it "has :a as its only marker" do
            node.markers.should have_markers(:a)
          end
        end

        describe "[2]" do
          before do
            @node = nodes[2]
          end

          it "has a key of 6 and a height of 1" do
            node.key.should == 6
            node.height.should == 1
          end

          it "has :z as its only forward marker at level 0" do
            node.forward_markers[0].should have_markers(:z)
          end

          it "has no markers" do
            node.markers.should be_empty
          end
        end

        describe "[3]" do
          before do
            @node = nodes[3]
          end

          it "has a key of 10 and height of 3" do
            node.key.should == 10
            node.height.should == 3
          end

          it "has no forward markers at any level" do
            node.forward_markers[0].should be_empty
            node.forward_markers[1].should be_empty
            node.forward_markers[2].should be_empty
          end

          it "has :z as its only marker" do
            node.markers.should have_markers(:z)
          end
        end
      end
    end
  end
end
