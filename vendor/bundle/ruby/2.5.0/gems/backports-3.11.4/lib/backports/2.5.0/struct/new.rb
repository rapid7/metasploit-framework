if RUBY_VERSION >= '2.0.0' && (Struct.new(:a, :keyword_init => true) && false rescue true)
  require 'backports/tools/alias_method_chain'
  eval %q[
  class << Struct
    def new_with_keyword_init(*members, keyword_init: false, &block)
      klass = new_without_keyword_init(*members)
      if keyword_init
        members.shift unless members.first.is_a?(Symbol)
        arg_list = members.map { |m| "#{m}: nil"}.join(', ')
        setter = members.map { |m| "self.#{m} = #{m} " }.join("\n")
        klass.class_eval <<-RUBY, __FILE__, __LINE__ + 1
          def initialize(#{arg_list})
            #{setter}
          end
        RUBY
      end
      klass.class_eval(&block) if block
      klass
    end
    Backports.alias_method_chain(self, :new, :keyword_init)
  end
  ]
end
