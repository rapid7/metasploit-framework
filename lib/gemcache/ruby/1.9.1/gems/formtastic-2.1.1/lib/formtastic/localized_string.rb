module Formtastic
  module LocalizedString

    def model_name
      @object.present? ? @object.class.name : @object_name.to_s.classify
    end

    protected

    def localized_string(key, value, type, options = {}) #:nodoc:
      current_builder = respond_to?(:builder) ? builder : self
      localizer = Formtastic::FormBuilder.i18n_localizer.new(current_builder)
      localizer.localize(key, value, type, options)
    end

  end
end
