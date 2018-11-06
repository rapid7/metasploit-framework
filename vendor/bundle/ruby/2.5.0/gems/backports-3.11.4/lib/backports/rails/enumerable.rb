module Enumerable
  # Standard in rails... See official documentation[http://api.rubyonrails.org/classes/Enumerable.html]
  # Modified from rails 2.3 to not rely on size
  def sum(identity = 0, &block)
    if block_given?
      map(&block).sum(identity)
    else
      inject { |sum, element| sum + element } || identity
    end
  end unless method_defined? :sum

end
