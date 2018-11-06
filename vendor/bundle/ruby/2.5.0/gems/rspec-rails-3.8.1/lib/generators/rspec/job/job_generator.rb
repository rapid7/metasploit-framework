require 'generators/rspec'

module Rspec
  module Generators
    # @private
    class JobGenerator < Base
      def create_job_spec
        template 'job_spec.rb.erb', File.join('spec/jobs', class_path, "#{file_name}_job_spec.rb")
      end
    end
  end
end
