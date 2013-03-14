module Formtastic
  # @private
  module HtmlAttributes

    protected

    def humanized_attribute_name(method)
      if @object && @object.class.respond_to?(:human_attribute_name)
        humanized_name = @object.class.human_attribute_name(method.to_s)
        if humanized_name == method.to_s.send(:humanize)
          method.to_s.send(label_str_method)
        else
          humanized_name
        end
      else
        method.to_s.send(label_str_method)
      end
    end

  end
end