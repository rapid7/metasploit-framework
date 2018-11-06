RSpec::Support.require_rspec_support "directory_maker"

module RSpec
  module Core
    # @private
    # Generates conventional files for an RSpec project.
    class ProjectInitializer
      attr_reader :destination, :stream, :template_path

      DOT_RSPEC_FILE = '.rspec'
      SPEC_HELPER_FILE =  'spec/spec_helper.rb'

      def initialize(opts={})
        @destination = opts.fetch(:destination, Dir.getwd)
        @stream = opts.fetch(:report_stream, $stdout)
        @template_path = opts.fetch(:template_path) do
          File.expand_path("../project_initializer", __FILE__)
        end
      end

      def run
        copy_template DOT_RSPEC_FILE
        copy_template SPEC_HELPER_FILE
      end

    private

      def copy_template(file)
        destination_file = File.join(destination, file)
        return report_exists(file) if File.exist?(destination_file)

        report_creating(file)
        RSpec::Support::DirectoryMaker.mkdir_p(File.dirname(destination_file))
        File.open(destination_file, 'w') do |f|
          f.write File.read(File.join(template_path, file))
        end
      end

      def report_exists(file)
        stream.puts "   exist   #{file}"
      end

      def report_creating(file)
        stream.puts "  create   #{file}"
      end
    end
  end
end
