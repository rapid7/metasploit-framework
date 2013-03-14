module Shared
  module List
    def setup
      (1..4).each { |counter| ListMixin.create! :pos => counter, :parent_id => 5 }
    end

    def test_reordering
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).move_lower
      assert_equal [1, 3, 2, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).move_higher
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(1).move_to_bottom
      assert_equal [2, 3, 4, 1], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(1).move_to_top
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).move_to_bottom
      assert_equal [1, 3, 4, 2], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(4).move_to_top
      assert_equal [4, 1, 3, 2], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)
    end

    def test_move_to_bottom_with_next_to_last_item
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)
      ListMixin.find(3).move_to_bottom
      assert_equal [1, 2, 4, 3], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)
    end

    def test_next_prev
      assert_equal ListMixin.find(2), ListMixin.find(1).lower_item
      assert_nil ListMixin.find(1).higher_item
      assert_equal ListMixin.find(3), ListMixin.find(4).higher_item
      assert_nil ListMixin.find(4).lower_item
    end

    def test_injection
      item = ListMixin.new(:parent_id => 1)
      assert_equal '"mixins"."parent_id" = 1', item.scope_condition
      assert_equal "pos", item.position_column
    end

    def test_insert
      new = ListMixin.create(:parent_id => 20)
      assert_equal 1, new.pos
      assert new.first?
      assert new.last?

      new = ListMixin.create(:parent_id => 20)
      assert_equal 2, new.pos
      assert !new.first?
      assert new.last?

      new = ListMixin.create(:parent_id => 20)
      assert_equal 3, new.pos
      assert !new.first?
      assert new.last?

      new = ListMixin.create(:parent_id => 0)
      assert_equal 1, new.pos
      assert new.first?
      assert new.last?
    end

    def test_insert_at
      new = ListMixin.create(:parent_id => 20)
      assert_equal 1, new.pos

      new = ListMixin.create(:parent_id => 20)
      assert_equal 2, new.pos

      new = ListMixin.create(:parent_id => 20)
      assert_equal 3, new.pos

      new4 = ListMixin.create(:parent_id => 20)
      assert_equal 4, new4.pos

      new4.insert_at(3)
      assert_equal 3, new4.pos

      new.reload
      assert_equal 4, new.pos

      new.insert_at(2)
      assert_equal 2, new.pos

      new4.reload
      assert_equal 4, new4.pos

      new5 = ListMixin.create(:parent_id => 20)
      assert_equal 5, new5.pos

      new5.insert_at(1)
      assert_equal 1, new5.pos

      new4.reload
      assert_equal 5, new4.pos
    end

    def test_insert_middle_with_unsaved_item
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      # new item, not saved yet
      insert_this = ListMixin.new(:parent_id => 5)
      insert_this.insert_at(2)

      assert_equal [1, 2, 3, 4, 5], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:pos)
      assert_equal [1, 5, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)
    end

    def test_delete_middle
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).destroy

      assert_equal [1, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      assert_equal 1, ListMixin.find(1).pos
      assert_equal 2, ListMixin.find(3).pos
      assert_equal 3, ListMixin.find(4).pos

      ListMixin.find(1).destroy

      assert_equal [3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      assert_equal 1, ListMixin.find(3).pos
      assert_equal 2, ListMixin.find(4).pos
    end

    def test_with_string_based_scope
      new = ListWithStringScopeMixin.create(:parent_id => 500)
      assert_equal 1, new.pos
      assert new.first?
      assert new.last?
    end

    def test_nil_scope
      new1, new2, new3 = ListMixin.create, ListMixin.create, ListMixin.create
      new2.move_higher
      assert_equal [new2, new1, new3], ListMixin.find(:all, :conditions => 'parent_id IS NULL', :order => 'pos')
    end

    def test_remove_from_list_should_then_fail_in_list?
      assert_equal true, ListMixin.find(1).in_list?
      ListMixin.find(1).remove_from_list
      assert_equal false, ListMixin.find(1).in_list?
    end

    def test_remove_from_list_should_set_position_to_nil
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).remove_from_list

      assert_equal [2, 1, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      assert_equal 1,   ListMixin.find(1).pos
      assert_equal nil, ListMixin.find(2).pos
      assert_equal 2,   ListMixin.find(3).pos
      assert_equal 3,   ListMixin.find(4).pos
    end

    def test_remove_before_destroy_does_not_shift_lower_items_twice
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      ListMixin.find(2).remove_from_list
      ListMixin.find(2).destroy

      assert_equal [1, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      assert_equal 1, ListMixin.find(1).pos
      assert_equal 2, ListMixin.find(3).pos
      assert_equal 3, ListMixin.find(4).pos
    end

    def test_before_destroy_callbacks_do_not_update_position_to_nil_before_deleting_the_record
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      # We need to trigger all the before_destroy callbacks without actually
      # destroying the record so we can see the affect the callbacks have on
      # the record.
      # NOTE: Hotfix for rails3 ActiveRecord
      list = ListMixin.find(2)
      if list.respond_to?(:run_callbacks)
        # Refactored to work according to Rails3 ActiveRSupport Callbacks <http://api.rubyonrails.org/classes/ActiveSupport/Callbacks.html>
        list.run_callbacks :destroy, :before if rails_3
        list.run_callbacks(:before_destroy) if !rails_3
      else
        list.send(:callback, :before_destroy)
      end

      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      assert_equal 1, ListMixin.find(1).pos
      assert_equal 2, ListMixin.find(2).pos
      assert_equal 2, ListMixin.find(3).pos
      assert_equal 3, ListMixin.find(4).pos
    end

    def test_before_create_callback_adds_to_bottom
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      new = ListMixin.create(:parent_id => 5)
      assert_equal 5, new.pos
      assert !new.first?
      assert new.last?

      assert_equal [1, 2, 3, 4, 5], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)
    end

    def test_before_create_callback_adds_to_given_position
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      new = ListMixin.create(:pos => 1, :parent_id => 5)
      assert_equal 1, new.pos
      assert new.first?
      assert !new.last?

      assert_equal [5, 1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)

      new = ListMixin.create(:pos => 3, :parent_id => 5)
      assert_equal 3, new.pos
      assert !new.first?
      assert !new.last?

      assert_equal [5, 1, 6, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5', :order => 'pos').map(&:id)
    end
  end
end
