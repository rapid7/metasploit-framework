module Shared
  module ListSub
    def setup
      (1..4).each { |i| ((i % 2 == 1) ? ListMixinSub1 : ListMixinSub2).create! :pos => i, :parent_id => 5000 }
    end

    def test_reordering
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      ListMixin.find(2).move_lower
      assert_equal [1, 3, 2, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      ListMixin.find(2).move_higher
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      ListMixin.find(1).move_to_bottom
      assert_equal [2, 3, 4, 1], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      ListMixin.find(1).move_to_top
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      ListMixin.find(2).move_to_bottom
      assert_equal [1, 3, 4, 2], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      ListMixin.find(4).move_to_top
      assert_equal [4, 1, 3, 2], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)
    end

    def test_move_to_bottom_with_next_to_last_item
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)
      ListMixin.find(3).move_to_bottom
      assert_equal [1, 2, 4, 3], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)
    end

    def test_next_prev
      assert_equal ListMixin.find(2), ListMixin.find(1).lower_item
      assert_nil ListMixin.find(1).higher_item
      assert_equal ListMixin.find(3), ListMixin.find(4).higher_item
      assert_nil ListMixin.find(4).lower_item
    end

    def test_injection
      item = ListMixin.new("parent_id"=>1)
      assert_equal '"mixins"."parent_id" = 1', item.scope_condition
      assert_equal "pos", item.position_column
    end

    def test_insert_at
      new = ListMixin.create("parent_id" => 20)
      assert_equal 1, new.pos

      new = ListMixinSub1.create("parent_id" => 20)
      assert_equal 2, new.pos

      new = ListMixinSub2.create("parent_id" => 20)
      assert_equal 3, new.pos

      new4 = ListMixin.create("parent_id" => 20)
      assert_equal 4, new4.pos

      new4.insert_at(3)
      assert_equal 3, new4.pos

      new.reload
      assert_equal 4, new.pos

      new.insert_at(2)
      assert_equal 2, new.pos

      new4.reload
      assert_equal 4, new4.pos

      new5 = ListMixinSub1.create("parent_id" => 20)
      assert_equal 5, new5.pos

      new5.insert_at(1)
      assert_equal 1, new5.pos

      new4.reload
      assert_equal 5, new4.pos
    end

    def test_delete_middle
      assert_equal [1, 2, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      ListMixin.find(2).destroy

      assert_equal [1, 3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      assert_equal 1, ListMixin.find(1).pos
      assert_equal 2, ListMixin.find(3).pos
      assert_equal 3, ListMixin.find(4).pos

      ListMixin.find(1).destroy

      assert_equal [3, 4], ListMixin.find(:all, :conditions => 'parent_id = 5000', :order => 'pos').map(&:id)

      assert_equal 1, ListMixin.find(3).pos
      assert_equal 2, ListMixin.find(4).pos
    end
  end
end
