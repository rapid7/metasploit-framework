module PalindromicFixtureSharedContext
  extend RSpec::Core::SharedContext
  include IntervalSkipListSpecHelper

  attr_reader :list, :node

  def construct_interval_skip_list
    @list = IntervalSkipList.new
  end

  def expected_node_heights
    [3, 2, 1, 3, 1, 2, 3]
  end

  def populate_interval_skip_list
    @list.insert(1..3, :a)
    @list.insert(1..5, :b)
    @list.insert(1..7, :c)
    @list.insert(1..9, :d)
    @list.insert(1..11, :e)
    @list.insert(1..13, :f)
    @list.insert(5..13, :g)
  end

  def make_it_determinisitic
    extend NextNodeHeightIsDeterministicSharedContext # use the method without getting the filter
    next_node_height_is_deterministic
  end

  before :each do
    construct_interval_skip_list
    make_it_determinisitic
    populate_interval_skip_list
  end
end
