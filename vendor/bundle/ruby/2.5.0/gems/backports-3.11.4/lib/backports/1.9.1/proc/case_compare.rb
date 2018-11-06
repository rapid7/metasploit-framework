unless Proc.new{true} === 42
  class Proc
    # Standard in Ruby 1.9. See official documentation[http://ruby-doc.org/core-1.9/classes/Proc.html]
    alias_method :===, :call
  end
end
