unless Array.method_defined? :select!
  class Array
    def select!
      return to_enum(:select!) unless block_given?
      reject!{|elem| ! yield elem}
    end
  end
end
