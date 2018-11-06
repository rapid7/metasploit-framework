# For Ruby 1.8
unless :symbol.respond_to?(:downcase)
  Symbol.class_eval do
    def downcase
      to_s.downcase.intern
    end
  end
end
