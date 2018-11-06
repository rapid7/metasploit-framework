require 'helper'

test_case PropertyHash do

  class_method :new do
    test do
      PropertyHash.new
    end
  end

  method :update do
    test do
      h = PropertyHash.new
      h.property :a
      h.property :b
      h.update(:a=>1, :b=>2)
      h.assert == {:a=>1, :b=>2}
    end
  end

end
