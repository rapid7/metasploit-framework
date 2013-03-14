# encoding: utf-8

require 'active_model/validator'
require 'active_support/concern'

module CarrierWave

  # == Active Model Presence Validator
  module Validations
    module ActiveModel
      extend ActiveSupport::Concern

      class ProcessingValidator < ::ActiveModel::EachValidator

        def validate_each(record, attribute, value)
          if e = record.send("#{attribute}_processing_error")
            message = (e.message == e.class.to_s) ? :carrierwave_processing_error : e.message
            record.errors.add(attribute, message)
          end
        end
      end

      class IntegrityValidator < ::ActiveModel::EachValidator

        def validate_each(record, attribute, value)
          if e = record.send("#{attribute}_integrity_error")
            message = (e.message == e.class.to_s) ? :carrierwave_integrity_error : e.message
            record.errors.add(attribute, message)
          end
        end
      end

      module HelperMethods

        ##
        # Makes the record invalid if the file couldn't be uploaded due to an integrity error
        #
        # Accepts the usual parameters for validations in Rails (:if, :unless, etc...)
        #
        def validates_integrity_of(*attr_names)
          validates_with IntegrityValidator, _merge_attributes(attr_names)
        end

        ##
        # Makes the record invalid if the file couldn't be processed (assuming the process failed
        # with a CarrierWave::ProcessingError)
        #
        # Accepts the usual parameters for validations in Rails (:if, :unless, etc...)
        #
        def validates_processing_of(*attr_names)
          validates_with ProcessingValidator, _merge_attributes(attr_names)
        end
      end

      included do
        extend HelperMethods
        include HelperMethods
      end
    end
  end
end

I18n.load_path << File.join(File.dirname(__FILE__), "..", "locale", 'en.yml')
