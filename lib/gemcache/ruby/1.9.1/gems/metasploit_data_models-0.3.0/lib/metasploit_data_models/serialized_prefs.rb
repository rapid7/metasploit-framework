module MetasploitDataModels
  module SerializedPrefs
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
end
