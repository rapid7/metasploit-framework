module Formtastic
  module Helpers
    # @private
    module FileColumnDetection

      def is_file?(method, options = {})
        @files ||= {}
        @files[method] ||= (options[:as].present? && options[:as] == :file) || begin
          file = @object.send(method) if @object && @object.respond_to?(method)
          file && file_methods.any?{|m| file.respond_to?(m)}
        end
      end

    end
  end
end