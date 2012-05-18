#require 'runtime/interval_skip_list/spec_helper'
#
#MAX_INTERVAL = 100000
#
#describe IntervalSkipList do
#  describe "#next_node_height" do
#    attr_reader :list
#
#    before do
#      @list = IntervalSkipList.new
#    end
#
#    it "returns a number between 1 and the max_height of the list" do
#      height = list.next_node_height
#      height.should be <= list.max_height
#      height.should be > 0
#    end
#  end
#
#  describe "a list with 1000 random intervals" do
#    attr_reader :list, :inserted_ranges
#
#    before do
#      @list = IntervalSkipList.new
#      @inserted_ranges = []
#
#      0.upto(10) do |i|
#        first, last = [rand(MAX_INTERVAL), rand(MAX_INTERVAL)].sort
#        range = first..last
#        list.insert(range, i)
#        inserted_ranges.push(range)
#      end
#    end
#
#    it "functions correctly for stabbing queries" do
#      10000.times do
#        n = rand(MAX_INTERVAL)
#        ranges = list.containing(n).sort
#
#        expected_ranges = []
#        inserted_ranges.each_with_index do |range,i|
#          expected_ranges.push(i) if n > range.first && n < range.last
#        end
#        expected_ranges.sort!
#        unless ranges == expected_ranges
#          puts "N = #{n}"
#          puts "Expected: " + expected_ranges.inspect
#          puts "Actual:   " + ranges.inspect
#          expected_ranges.size.should be <= ranges.size
#          puts "Missing containers: #{(expected_ranges.map {|o| o.object_id} - ranges.map {|o| o.object_id}).inspect}"
#          puts "Unexpected containers: #{(ranges.map {|o| o.object_id} - expected_ranges.map {|o| o.object_id}).inspect}"
#          puts "Inserted Ranges: #{inserted_ranges.inspect}"
#          puts "Expected Ranges: #{expected_ranges.map {|i| inserted_ranges[i]}.inspect}"
#        end
#      end
#    end
#  end
#end
