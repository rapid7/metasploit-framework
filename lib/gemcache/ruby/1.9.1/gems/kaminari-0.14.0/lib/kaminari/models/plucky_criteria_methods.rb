module Kaminari
  module PluckyCriteriaMethods
    include Kaminari::PageScopeMethods
    include Kaminari::ConfigurationMethods::ClassMethods

    def limit_value #:nodoc:
      options[:limit]
    end

    def offset_value #:nodoc:
      options[:skip]
    end

    def total_count #:nodoc:
      count
    end
  end
end
