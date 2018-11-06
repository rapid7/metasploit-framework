require 'helper'

test_case CRUDHash do

  class_method :create do
    test do
      h = CRUDHash.create(:a=>1,:b=>2)
      h.assert == {:a=>1,:b=>2}
    end
  end

  class_method :auto do
    test 'without a block' do
      h = CRUDHash.auto
      h[:a].assert == {}
    end

    test 'with a block' do
      h = CRUDHash.auto{ [] }
      h[:a].assert == []
    end
  end

end


#
# OT: Why not make `:a=>1` a Pair object?
#
