unless Hash.method_defined? :to_proc
  class Hash
    def to_proc
      h = self
      Proc.new{|*args| h[*args]}
    end
  end
end
