# Allows attributes to be extracted and written to key of serialized `Hash` `prefs`.
module MetasploitDataModels::SerializedPrefs
  # Setup each arg in `args` as the name of an attribute embedded in the `prefs` `Hash`.  Defines `#<arg>` and
  # `#<arg>=(value)` methods like standard `attr_accessor`.
  #
  # @param args [Array<Symbol>] The names of the attributes to store in the `prefs` `Hash`.
  # @return [void]
  def serialized_prefs_attr_accessor(*args)
    args.each do |method_name|

      method_declarations = <<-RUBY
          def #{method_name}
            return if not self.prefs
            self.prefs[:#{method_name}]
          end

          def #{method_name}=(value)
            temp = self.prefs || {}
            temp[:#{method_name}] = value
            self.prefs = temp
          end
      RUBY

      class_eval method_declarations, __FILE__, __LINE__
    end
  end
end