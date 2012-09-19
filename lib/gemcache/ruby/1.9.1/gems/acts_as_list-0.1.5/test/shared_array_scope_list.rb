module Shared
  module ArrayScopeList
    def setup
      (1..4).each { |counter| ArrayScopeListMixin.create! :pos => counter, :parent_id => 5, :parent_type => 'ParentClass' }
    end

    def test_reordering
      assert_equal [1, 2, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(2).move_lower
      assert_equal [1, 3, 2, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(2).move_higher
      assert_equal [1, 2, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(1).move_to_bottom
      assert_equal [2, 3, 4, 1], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(1).move_to_top
      assert_equal [1, 2, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(2).move_to_bottom
      assert_equal [1, 3, 4, 2], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(4).move_to_top
      assert_equal [4, 1, 3, 2], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)
    end

    def test_move_to_bottom_with_next_to_last_item
      assert_equal [1, 2, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)
      ArrayScopeListMixin.find(3).move_to_bottom
      assert_equal [1, 2, 4, 3], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)
    end

    def test_next_prev
      assert_equal ArrayScopeListMixin.find(2), ArrayScopeListMixin.find(1).lower_item
      assert_nil ArrayScopeListMixin.find(1).higher_item
      assert_equal ArrayScopeListMixin.find(3), ArrayScopeListMixin.find(4).higher_item
      assert_nil ArrayScopeListMixin.find(4).lower_item
    end

    def test_injection
      item = ArrayScopeListMixin.new(:parent_id => 1, :parent_type => 'ParentClass')
      assert_equal '"mixins"."parent_id" = 1 AND "mixins"."parent_type" = \'ParentClass\'', item.scope_condition
      assert_equal "pos", item.position_column
    end

    def test_insert
      new = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 1, new.pos
      assert new.first?
      assert new.last?

      new = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 2, new.pos
      assert !new.first?
      assert new.last?

      new = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 3, new.pos
      assert !new.first?
      assert new.last?

      new = ArrayScopeListMixin.create(:parent_id => 0, :parent_type => 'ParentClass')
      assert_equal 1, new.pos
      assert new.first?
      assert new.last?
    end

    def test_insert_at
      new = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 1, new.pos

      new = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 2, new.pos

      new = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 3, new.pos

      new4 = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 4, new4.pos

      new4.insert_at(3)
      assert_equal 3, new4.pos

      new.reload
      assert_equal 4, new.pos

      new.insert_at(2)
      assert_equal 2, new.pos

      new4.reload
      assert_equal 4, new4.pos

      new5 = ArrayScopeListMixin.create(:parent_id => 20, :parent_type => 'ParentClass')
      assert_equal 5, new5.pos

      new5.insert_at(1)
      assert_equal 1, new5.pos

      new4.reload
      assert_equal 5, new4.pos
    end

    def test_delete_middle
      assert_equal [1, 2, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(2).destroy

      assert_equal [1, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      assert_equal 1, ArrayScopeListMixin.find(1).pos
      assert_equal 2, ArrayScopeListMixin.find(3).pos
      assert_equal 3, ArrayScopeListMixin.find(4).pos

      ArrayScopeListMixin.find(1).destroy

      assert_equal [3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      assert_equal 1, ArrayScopeListMixin.find(3).pos
      assert_equal 2, ArrayScopeListMixin.find(4).pos
    end

    def test_remove_from_list_should_then_fail_in_list?
      assert_equal true, ArrayScopeListMixin.find(1).in_list?
      ArrayScopeListMixin.find(1).remove_from_list
      assert_equal false, ArrayScopeListMixin.find(1).in_list?
    end

    def test_remove_from_list_should_set_position_to_nil
      assert_equal [1, 2, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(2).remove_from_list

      assert_equal [2, 1, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      assert_equal 1,   ArrayScopeListMixin.find(1).pos
      assert_equal nil, ArrayScopeListMixin.find(2).pos
      assert_equal 2,   ArrayScopeListMixin.find(3).pos
      assert_equal 3,   ArrayScopeListMixin.find(4).pos
    end

    def test_remove_before_destroy_does_not_shift_lower_items_twice
      assert_equal [1, 2, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      ArrayScopeListMixin.find(2).remove_from_list
      ArrayScopeListMixin.find(2).destroy

      assert_equal [1, 3, 4], ArrayScopeListMixin.find(:all, :conditions => "parent_id = 5 AND parent_type = 'ParentClass'", :order => 'pos').map(&:id)

      assert_equal 1, ArrayScopeListMixin.find(1).pos
      assert_equal 2, ArrayScopeListMixin.find(3).pos
      assert_equal 3, ArrayScopeListMixin.find(4).pos
    end
  end
end
