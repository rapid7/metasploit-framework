unless Symbol < Comparable
  class Symbol
    alias_method :dont_override_equal_please, :==
    include Comparable
    alias_method :==,  :dont_override_equal_please
  end
end
