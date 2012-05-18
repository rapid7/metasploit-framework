module Shared
  module ZeroBased
    def setup
       (1..4).each { |counter| ZeroBasedMixin.create! :pos => counter, :parent_id => 5 }
    end

    def test_insert
      new = ZeroBasedMixin.create(:parent_id => 20)
      assert_equal 0, new.pos
      assert new.first?
      assert new.last?

      new = ZeroBasedMixin.create(:parent_id => 20)
      assert_equal 1, new.pos
      assert !new.first?
      assert new.last?

      new = ZeroBasedMixin.create(:parent_id => 20)
      assert_equal 2, new.pos
      assert !new.first?
      assert new.last?

      new = ZeroBasedMixin.create(:parent_id => 0)
      assert_equal 0, new.pos
      assert new.first?
      assert new.last?
    end

    def test_reordering
      assert_equal [1, 2, 3, 4], ZeroBasedMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).move_lower
      assert_equal [1, 3, 2, 4], ZeroBasedMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).move_higher
      assert_equal [1, 2, 3, 4], ZeroBasedMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(1).move_to_bottom
      assert_equal [2, 3, 4, 1], ZeroBasedMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(1).move_to_top
      assert_equal [1, 2, 3, 4], ZeroBasedMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).move_to_bottom
      assert_equal [1, 3, 4, 2], ZeroBasedMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(4).move_to_top
      assert_equal [4, 1, 3, 2], ZeroBasedMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)
    end

    def test_insert_at
      new = ZeroBasedMixin.create(:parent_id => 20)
      assert_equal 0, new.pos

      new = ZeroBasedMixin.create(:parent_id => 20)
      assert_equal 1, new.pos

      new = ZeroBasedMixin.create(:parent_id => 20)
      assert_equal 2, new.pos

      new4 = ZeroBasedMixin.create(:parent_id => 20)
      assert_equal 3, new4.pos

      new4.insert_at(2)
      assert_equal 2, new4.pos

      new.reload
      assert_equal 3, new.pos

      new.insert_at(2)
      assert_equal 2, new.pos

      new4.reload
      assert_equal 3, new4.pos

      new5 = ListMixin.create(:parent_id => 20)
      assert_equal 4, new5.pos

      new5.insert_at(1)
      assert_equal 1, new5.pos

      new4.reload
      assert_equal 4, new4.pos
    end
  end
end
