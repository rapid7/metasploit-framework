# NOTE: following now done in helper.rb (better Readability)
require 'helper'

ActiveRecord::Base.establish_connection(:adapter => "sqlite3", :database => ":memory:")
ActiveRecord::Schema.verbose = false

def setup_db(position_options = {})
  # AR caches columns options like defaults etc. Clear them!
  ActiveRecord::Base.connection.schema_cache.clear!
  ActiveRecord::Schema.define(:version => 1) do
    create_table :mixins do |t|
      t.column :pos, :integer, position_options
      t.column :parent_id, :integer
      t.column :parent_type, :string
      t.column :created_at, :datetime
      t.column :updated_at, :datetime
    end
  end
end

def setup_db_with_default
  setup_db :default => 0
end

# Returns true if ActiveRecord is rails3 version
def rails_3
  defined?(ActiveRecord::VERSION) && ActiveRecord::VERSION::MAJOR >= 3
end

def teardown_db
  ActiveRecord::Base.connection.tables.each do |table|
    ActiveRecord::Base.connection.drop_table(table)
  end
end

class Mixin < ActiveRecord::Base
  self.table_name = 'mixins'
end

class ListMixin < Mixin
  acts_as_list :column => "pos", :scope => :parent
end

class ListMixinSub1 < ListMixin
end

class ListMixinSub2 < ListMixin
  if rails_3
    validates :pos, :presence => true
  else
    validates_presence_of :pos
  end
end

class ListWithStringScopeMixin < Mixin
  acts_as_list :column => "pos", :scope => 'parent_id = #{parent_id}'
end

class ArrayScopeListMixin < Mixin
  acts_as_list :column => "pos", :scope => [:parent_id, :parent_type]
end

class ZeroBasedMixin < Mixin
  acts_as_list :column => "pos", :top_of_list => 0, :scope => [:parent_id]
end

class DefaultScopedMixin < Mixin
  acts_as_list :column => "pos"
  default_scope { order('pos ASC') }
end

class ActsAsListTestCase < Test::Unit::TestCase
  # No default test required a this class is abstract.
  # Need for test/unit.
  undef_method :default_test if method_defined?(:default_test)

  def teardown
    teardown_db
  end
end

class ZeroBasedTest < ActsAsListTestCase
  include Shared::ZeroBased

  def setup
    setup_db
    super
  end
end

class ZeroBasedTestWithDefault < ActsAsListTestCase
  include Shared::ZeroBased

  def setup
    setup_db_with_default
    super
  end
end

class ListTest < ActsAsListTestCase
  include Shared::List

  def setup
    setup_db
    super
  end
end

class ListTestWithDefault < ActsAsListTestCase
  include Shared::List

  def setup
    setup_db_with_default
    super
  end
end

class ListSubTest < ActsAsListTestCase
  include Shared::ListSub

  def setup
    setup_db
    super
  end
end

class ListSubTestWithDefault < ActsAsListTestCase
  include Shared::ListSub

  def setup
    setup_db_with_default
    super
  end
end

class ArrayScopeListTest < ActsAsListTestCase
  include Shared::ArrayScopeList

  def setup
    setup_db
    super
  end
end

class ArrayScopeListTestWithDefault < ActsAsListTestCase
  include Shared::ArrayScopeList

  def setup
    setup_db_with_default
    super
  end
end

class DefaultScopedTest < ActsAsListTestCase
  def setup
    setup_db
    (1..4).each { |counter| DefaultScopedMixin.create! :pos => counter }
  end

  def test_insert
    new = DefaultScopedMixin.create
    assert_equal 5, new.pos
    assert !new.first?
    assert new.last?

    new = DefaultScopedMixin.create
    assert_equal 6, new.pos
    assert !new.first?
    assert new.last?

    new = DefaultScopedMixin.create
    assert_equal 7, new.pos
    assert !new.first?
    assert new.last?
  end

  def test_reordering
    assert_equal [1, 2, 3, 4], DefaultScopedMixin.find(:all).map(&:id)

    DefaultScopedMixin.find(2).move_lower
    assert_equal [1, 3, 2, 4], DefaultScopedMixin.find(:all).map(&:id)

    DefaultScopedMixin.find(2).move_higher
    assert_equal [1, 2, 3, 4], DefaultScopedMixin.find(:all).map(&:id)

    DefaultScopedMixin.find(1).move_to_bottom
    assert_equal [2, 3, 4, 1], DefaultScopedMixin.find(:all).map(&:id)

    DefaultScopedMixin.find(1).move_to_top
    assert_equal [1, 2, 3, 4], DefaultScopedMixin.find(:all).map(&:id)

    DefaultScopedMixin.find(2).move_to_bottom
    assert_equal [1, 3, 4, 2], DefaultScopedMixin.find(:all).map(&:id)

    DefaultScopedMixin.find(4).move_to_top
    assert_equal [4, 1, 3, 2], DefaultScopedMixin.find(:all).map(&:id)
  end

  def test_insert_at
    new = DefaultScopedMixin.create
    assert_equal 5, new.pos

    new = DefaultScopedMixin.create
    assert_equal 6, new.pos

    new = DefaultScopedMixin.create
    assert_equal 7, new.pos

    new4 = DefaultScopedMixin.create
    assert_equal 8, new4.pos

    new4.insert_at(2)
    assert_equal 2, new4.pos

    new.reload
    assert_equal 8, new.pos

    new.insert_at(2)
    assert_equal 2, new.pos

    new4.reload
    assert_equal 3, new4.pos

    new5 = DefaultScopedMixin.create
    assert_equal 9, new5.pos

    new5.insert_at(1)
    assert_equal 1, new5.pos

    new4.reload
    assert_equal 4, new4.pos
  end

end
