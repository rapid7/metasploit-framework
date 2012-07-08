class Spork::AppFramework::Rails < Spork::AppFramework

  def preload(&block)
    STDERR.puts "Preloading Rails environment"
    STDERR.flush
    ENV["RAILS_ENV"] ||= 'test'
    preload_rails
    yield
  end

  def entry_point
    @entry_point ||= File.expand_path("config/environment.rb", Dir.pwd)
  end

  alias :environment_file :entry_point

  def boot_file
    @boot_file ||= File.join(File.dirname(environment_file), 'boot')
  end

  def application_file
    @application_file ||= File.join(File.dirname(environment_file), 'application')
  end

  def environment_contents
    @environment_contents ||= File.read(environment_file)
  end

  def vendor
    @vendor ||= File.expand_path("vendor/rails", Dir.pwd)
  end

  def deprecated_version
    @version ||= (
      if /^[^#]*RAILS_GEM_VERSION\s*=\s*["']([!~<>=]*\s*[\d.]+)["']/.match(environment_contents)
        $1
      else
        nil
      end
    )
  end

  def preload_rails
    if deprecated_version && (not /^3/.match(deprecated_version))
      puts "This version of spork only supports Rails 3.0. To use spork with rails 2.3.x, downgrade to spork 0.8.x."
      exit 1
    end
    require application_file
    ::Rails.application
    ::Rails::Engine.class_eval do
      def eager_load!
        # turn off eager_loading, all together
      end
    end
    # Spork.trap_method(::AbstractController::Helpers::ClassMethods, :helper)
    Spork.trap_method(::ActiveModel::Observing::ClassMethods, :instantiate_observers)
    Spork.each_run { ActiveRecord::Base.establish_connection rescue nil } if Object.const_defined?(:ActiveRecord)


    AbstractController::Helpers::ClassMethods.module_eval do
      def helper(*args, &block)
        ([args].flatten - [:all]).each do |arg|
          next unless arg.is_a?(String)
          filename = arg + "_helper"
          unless ::ActiveSupport::Dependencies.search_for_file(filename)
            # this error message must raise in the format such that LoadError#path returns the filename
            raise LoadError.new("Missing helper file helpers/%s.rb" % filename)
          end
        end

        Spork.each_run(false) do
          modules_for_helpers(args).each do |mod|
            add_template_helper(mod)
          end

          _helpers.module_eval(&block) if block_given?
        end
      end
    end
  end

end
