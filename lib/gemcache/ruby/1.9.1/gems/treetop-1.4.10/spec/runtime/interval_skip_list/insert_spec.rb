require 'runtime/interval_skip_list/spec_helper'

describe IntervalSkipList, " when #next_node_height returns 1, 3, 2, 3, 1 in order", :deterministic => true do
  include IntervalSkipListSpecHelper
  attr_reader :list, :node

  before do
    @list = IntervalSkipList.new
  end

  include NextNodeHeightIsDeterministicSharedContext

  def expected_node_heights
    [1, 3, 2, 3, 1]
  end

  describe ", when :a is inserted on 1..7" do
    before do
      list.insert(1..7, :a)
    end

    describe ", #containing" do
      it "returns only :a from 2 through 6" do
        (2..6).should contain_marker(:a)
      end

      it "returns nothing at 1 and 7" do
        list.containing(1).should be_empty
        list.containing(7).should be_empty
      end
    end

    describe " #nodes[0]" do
      before do
        @node = list.nodes[0]
      end

      it "has a key of 1 and height of 1" do
        node.key.should == 1
        node.height.should == 1
      end

      it "has :a as its only marker at level 0" do
        node.forward_markers[0].should have_marker(:a)
      end

      it "has no markers" do
        node.markers.should be_empty
      end

      it "is an endpoint of only :a" do
        node.endpoint_of.should have_marker(:a)
      end
    end

    describe " #nodes[1]" do
      before do
        @node = list.nodes[1]
      end

      it "has a key of 7 and height of 3" do
        node.key.should == 7
        node.height.should == 3
      end

      it "has no forward markers at any level" do
        node.forward_markers[0].should be_empty
        node.forward_markers[1].should be_empty
        node.forward_markers[2].should be_empty
      end

      it "has :a as its only marker" do
        node.markers.should have_marker(:a)
      end

      it "is an endpoint of only :a" do
        node.endpoint_of.should have_marker(:a)
      end
    end

    describe ", and then :b is inserted on 1..5" do
      before do
        list.insert(1..5, :b)
      end

      describe ", #containing" do
        it "returns only :a and :b from 2 through 4" do
          (2..4).should contain_markers(:a, :b)
        end

        it "returns only :a from 5 through 6" do
          (5..6).should contain_marker(:a)
        end

        it "returns nothing at 1 and 7" do
          list.containing(1).should be_empty
          list.containing(7).should be_empty
        end
      end

      describe " #nodes[0]" do
        before do
          @node = list.nodes[0]
        end

        it "has a key of 1 and height of 1" do
          node.key.should == 1
          node.height.should == 1
        end

        it "has :a and :b as its only forward markers at level 0" do
          node.forward_markers[0].should have_markers(:a, :b)
        end

        it "has no markers" do
          node.markers.should be_empty
        end

        it "is an endpoint of only :a and :b" do
          node.endpoint_of.should have_markers(:a, :b)
        end
      end

      describe " #nodes[1]" do
        before do
          @node = list.nodes[1]
        end

        it "has a key of 5 and height of 2" do
          node.key.should == 5
          node.height.should == 2
        end

        it "has :a as its only forward marker at level 1" do
          node.forward_markers[1].should have_marker(:a)
        end

        it "has no forward markers at level 0" do
          node.forward_markers[0].should be_empty
        end

        it "has :a and :b as its only markers" do
          node.markers.should have_markers(:a, :b)
        end

        it "is an endpoint of only :b" do
          node.endpoint_of.should have_marker(:b)
        end
      end

      describe " #nodes[2]" do
        before do
          @node = list.nodes[2]
        end

        it "has a key of 7 and height of 3" do
          node.key.should == 7
          node.height.should == 3
        end

        it "has no forward markers at any level" do
          node.forward_markers[0].should be_empty
          node.forward_markers[1].should be_empty
          node.forward_markers[2].should be_empty
        end

        it "has :a its only marker" do
          node.markers.should have_marker(:a)
        end

        it "is an endpoint of only :a" do
          node.endpoint_of.should have_marker(:a)
        end
      end

      describe ", and then :c is inserted on 1..3" do
        before do
          list.insert(1..3, :c)
        end

        describe ", #containing" do
          it "returns only :a, :b, and :c for 2" do
            (2..2).should contain_markers(:a, :b, :c)
          end

          it "returns only :a, :b from 3..4" do
            (3..4).should contain_markers(:a, :b)
          end

          it "returns only :a from 5..6" do
            (5..6).should contain_markers(:a)
          end

          it "returns nothing at 1 and 7" do
            list.containing(1).should be_empty
            list.containing(7).should be_empty
          end
        end

        describe " #nodes[0]" do
          before do
            @node = list.nodes[0]
          end

          it "has a key of 1 and height of 1" do
            node.key.should == 1
            node.height.should == 1
          end

          it "has :a, :b, :c as its only forward markers at level 0" do
            node.forward_markers[0].should have_markers(:a, :b, :c)
          end

          it "has no markers" do
            node.markers.should be_empty
          end

          it "is an endpoint of only :a, :b, :c" do
            node.endpoint_of.should have_markers(:a, :b, :c)
          end
        end

        describe " #nodes[1]" do
          before do
            @node = list.nodes[1]
          end

          it "has a key of 3 and height of 3" do
            node.key.should == 3
            node.height.should == 3
          end

          it "has :a as its only forward marker at level 2" do
            node.forward_markers[2].should have_marker(:a)
          end

          it "has :b as its only forward marker at level 1" do
            node.forward_markers[1].should have_marker(:b)
          end

          it "has no forward markers at level 0" do
            node.forward_markers[0].should be_empty
          end

          it "has :a, :b, and :c as its only markers" do
            node.markers.should have_markers(:a, :b, :c)
          end

          it "is an endpoint of only :c" do
            node.endpoint_of.should have_marker(:c)
          end
        end

        describe " #nodes[2]" do
          before do
            @node = list.nodes[2]
          end

          it "has a key of 5 and height of 2" do
            node.key.should == 5
            node.height.should == 2
          end

          it "has no forward markers at any level" do
            node.forward_markers[0].should be_empty
            node.forward_markers[1].should be_empty
          end

          it "has :b as its only markers" do
            node.markers.should have_marker(:b)
          end

          it "is an endpoint of only :b" do
            node.endpoint_of.should have_marker(:b)
          end
        end

        describe " #nodes[3]" do
          before do
            @node = list.nodes[3]
          end

          it "has a key of 7 and height of 3" do
            node.key.should == 7
            node.height.should == 3
          end

          it "has no forward markers at any level" do
            node.forward_markers[0].should be_empty
            node.forward_markers[1].should be_empty
            node.forward_markers[2].should be_empty
          end

          it "has :a as its only marker" do
            node.markers.should have_marker(:a)
          end

          it "is an endpoint of only :a" do
            node.endpoint_of.should have_marker(:a)
          end
        end

        describe ", and then :d is inserted on 1..9" do
          before do
            list.insert(1..9, :d)
          end

          describe ", #containing" do
            it "returns only :a, :b, :c, and :d for 2" do
              (2..2).should contain_markers(:a, :b, :c, :d)
            end

            it "returns only :a, :b from 3..4" do
              (3..4).should contain_markers(:a, :b, :d)
            end

            it "returns only :a from 5..6" do
              (5..6).should contain_markers(:a, :d)
            end

            it "returns only :a from 7..8" do
              (7..8).should contain_markers(:d)
            end

            it "returns nothing at 1 and 9" do
              list.containing(1).should be_empty
              list.containing(9).should be_empty
            end

            it "returns nothing for -1, 0, and 10" do
              list.containing(-1).should be_empty
              list.containing(0).should be_empty
              list.containing(10).should be_empty
            end
          end

          describe " #nodes[0]" do
            before do
              @node = list.nodes[0]
            end

            it "has a key of 1 and height of 1" do
              node.key.should == 1
              node.height.should == 1
            end

            it "has :a, :b, :c, :d as its only forward markers at level 0" do
              node.forward_markers[0].should have_markers(:a, :b, :c, :d)
            end

            it "has no markers" do
              node.markers.should be_empty
            end

            it "is an endpoint of only :a, :b, :c, and :d" do
              node.endpoint_of.should have_markers(:a, :b, :c, :d)
            end
          end

          describe " #nodes[1]" do
            before do
              @node = list.nodes[1]
            end

            it "has a key of 3 and height of 3" do
              node.key.should == 3
              node.height.should == 3
            end

            it "has :a and :d as its only forward markers at level 2" do
              node.forward_markers[2].should have_markers(:a, :d)
            end

            it "has :b as its only marker at level 1" do
              node.forward_markers[1].should have_marker(:b)
            end

            it "has no forward markers at level 0" do
              node.forward_markers[0].should be_empty
            end

            it "has :a, :b, :c, :d as its only markers" do
              node.markers.should have_markers(:a, :b, :c, :d)
            end

            it "is an endpoint of only :c" do
              node.endpoint_of.should have_marker(:c)
            end
          end

          describe " #nodes[2]" do
            before do
              @node = list.nodes[2]
            end

            it "has a key of 5 and height of 2" do
              node.key.should == 5
              node.height.should == 2
            end

            it "has no markers on any level" do
              node.forward_markers[0].should be_empty
              node.forward_markers[1].should be_empty
            end

            it "has :b as its only marker" do
              node.markers.should have_marker(:b)
            end

            it "is an endpoint of only :b" do
              node.endpoint_of.should have_marker(:b)
            end
          end

          describe " #nodes[3]" do
            before do
              @node = list.nodes[3]
            end

            it "has a key of 7 and height of 3" do
              node.key.should == 7
              node.height.should == 3
            end

            it "has :d as its only marker at level 0" do
              node.forward_markers[0].should have_marker(:d)
            end

            it "has no forward markers at levels 1 and 2" do
              node.forward_markers[1].should be_empty
              node.forward_markers[2].should be_empty
            end

            it "has :a, :d as its only markers" do
              node.markers.should have_markers(:a, :d)
            end

            it "is an endpoint of only :a" do
              node.endpoint_of.should have_marker(:a)
            end
          end

          describe " #nodes[4]" do
            before do
              @node = list.nodes[4]
            end

            it "has a key of 9 and height of 1" do
              node.key.should == 9
              node.height.should == 1
            end

            it "has no forward markers at level 0" do
              node.forward_markers[0].should be_empty
            end

            it "has :d as its only marker" do
              node.markers.should have_marker(:d)
            end

            it "is an endpoint of only :d" do
              node.endpoint_of.should have_marker(:d)
            end
          end

          describe ", and then :d is deleted" do
            before do
              list.delete(:d)
            end

            it "has only 4 nodes" do
              list.nodes.size.should == 4
            end

            describe " #nodes[0]" do
              before do
                @node = list.nodes[0]
              end

              it "has a key of 1 and height of 1" do
                node.key.should == 1
                node.height.should == 1
              end

              it "has :a, :b, and :c as its only forward markers at level 0" do
                node.forward_markers[0].should have_markers(:a, :b, :c)
              end
            end

            describe " #nodes[1]" do
              before do
                @node = list.nodes[1]
              end

              it "has a key of 3 and height of 3" do
                node.key.should == 3
                node.height.should == 3
              end

              it "has :a as its only forward marker at level 2" do
                node.forward_markers[2].should have_marker(:a)
              end

              it "has :b as its only forward marker at level 1" do
                node.forward_markers[1].should have_marker(:b)
              end

              it "has no forward markers at level 0" do
                node.forward_markers[0].should be_empty
              end

              it "has :a, :b, and :c as its only markers" do
                node.markers.should have_markers(:a, :b, :c)
              end

              it "is the endpoint of only :c" do
                node.endpoint_of.should have_marker(:c)
              end
            end

            describe " #nodes[2]" do
              before do
                @node = list.nodes[2]
              end

              it "has a key of 5 and height of 2" do
                node.key.should == 5
                node.height.should == 2
              end

              it "has no forward markers at any level" do
                node.forward_markers[0].should be_empty
                node.forward_markers[1].should be_empty
              end

              it "has :b as its only marker" do
                node.markers.should have_marker(:b)
              end

              it "is the endpoint of only :b" do
                node.endpoint_of.should have_marker(:b)
              end
            end

            describe " #nodes[3]" do
              before do
                @node = list.nodes[3]
              end

              it "has a key of 7 and height of 3" do
                node.key.should == 7
                node.height.should == 3
              end

              it "has no forward markers at any level" do
                node.forward_markers[0].should be_empty
                node.forward_markers[1].should be_empty
                node.forward_markers[2].should be_empty
              end

              it "has :a as its only marker" do
                node.markers.should have_marker(:a)
              end

              it "is the endpoint of only :a" do
                node.endpoint_of.should have_marker(:a)
              end
            end

            describe ", and then :c is deleted" do
              before do
                list.delete(:c)
              end

              it "has only 3 nodes" do
                list.nodes.size.should == 3
              end

              describe " #nodes[0]" do
                before do
                  @node = list.nodes[0]
                end

                it "has a key of 1 and height of 1" do
                  node.key.should == 1
                  node.height.should == 1
                end

                it "has :a and :b as its only forward markers at level 0" do
                  node.forward_markers[0].should have_markers(:a, :b)
                end

                it "has no markers" do
                  node.markers.should be_empty
                end

                it "is an endpoint of only :a and :b" do
                  node.endpoint_of.should have_markers(:a, :b)
                end
              end

              describe " #nodes[1]" do
                before do
                  @node = list.nodes[1]
                end

                it "has a key of 5 and height of 2" do
                  node.key.should == 5
                  node.height.should == 2
                end

                it "has :a as its only forward marker at level 1" do
                  node.forward_markers[1].should have_marker(:a)
                end

                it "has no forward markers at level 0" do
                  node.forward_markers[0].should be_empty
                end

                it "has :a and :b as its only markers" do
                  node.markers.should have_markers(:a, :b)
                end

                it "is an endpoint of only :b" do
                  node.endpoint_of.should have_marker(:b)
                end
              end

              describe " #nodes[2]" do
                before do
                  @node = list.nodes[2]
                end

                it "has a key of 7 and height of 3" do
                  node.key.should == 7
                  node.height.should == 3
                end

                it "has no forward markers at any level" do
                  node.forward_markers[0].should be_empty
                  node.forward_markers[1].should be_empty
                  node.forward_markers[2].should be_empty
                end

                it "has :a its only marker" do
                  node.markers.should have_marker(:a)
                end

                it "is an endpoint of only :a" do
                  node.endpoint_of.should have_marker(:a)
                end
              end
            end
          end
        end
      end
    end
  end
end

