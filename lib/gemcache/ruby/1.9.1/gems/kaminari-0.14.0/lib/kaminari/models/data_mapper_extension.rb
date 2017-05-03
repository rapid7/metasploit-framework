require 'kaminari/models/data_mapper_collection_methods'

module Kaminari
  module DataMapperExtension
    module Paginatable
      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{Kaminari.config.page_method_name}(num = 1)
          num = [num.to_i, 1].max - 1
          all(:limit => default_per_page, :offset => default_per_page * num).extend Paginating
        end
      RUBY
    end

    module Paginating
      include Kaminari::PageScopeMethods

      def all(options={})
        super.extend Paginating
      end

      def per(num)
        super.extend Paginating
      end
    end

    module Collection
      extend ActiveSupport::Concern
      included do
        include Kaminari::ConfigurationMethods::ClassMethods
        include Kaminari::DataMapperCollectionMethods
        include Paginatable
      end
    end

    module Model
      include Kaminari::ConfigurationMethods::ClassMethods
      include Paginatable

      def limit(val)
        all(:limit => val)
      end

      def offset(val)
        all(:offset => val)
      end
    end
  end
end
