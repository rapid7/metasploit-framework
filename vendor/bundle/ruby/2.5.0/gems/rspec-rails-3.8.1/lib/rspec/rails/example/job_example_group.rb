module RSpec
  module Rails
    # @api public
    # Container module for job spec functionality. It is only available if
    # ActiveJob has been loaded before it.
    module JobExampleGroup
      # This blank module is only necessary for YARD processing. It doesn't
      # handle the conditional `defined?` check below very well.
    end
  end
end

if defined?(ActiveJob)
  module RSpec
    module Rails
      # Container module for job spec functionality.
      module JobExampleGroup
        extend ActiveSupport::Concern
        include RSpec::Rails::RailsExampleGroup
      end
    end
  end
end
