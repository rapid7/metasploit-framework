class Spork::AppFramework
  # A hash of procs where the key is the class name, and the proc takes no arguments and returns true if it detects that said application framework is being used in the project.
  # 
  # The key :Rails maps to Spork::AppFramework::Rails
  #
  # This is used to reduce the amount of code needed to be loaded - only the detected application framework's support code is loaded.
  SUPPORTED_FRAMEWORKS = {
    :Padrino => lambda {
      File.exist?("config/boot.rb") && File.read("config/boot.rb").include?('PADRINO')
    },
    :Rails => lambda {
      File.exist?("config/environment.rb") && (
        File.read("config/environment.rb").include?('RAILS_GEM_VERSION') ||
        (File.exist?("config/application.rb") && File.read("config/application.rb").include?("Rails::Application"))
      )
    }
  } unless defined? SUPPORTED_FRAMEWORKS
  
  def self.setup_autoload
    ([:Unknown] + SUPPORTED_FRAMEWORKS.keys).each do |name|
      autoload name, File.join(File.dirname(__FILE__), "app_framework", name.to_s.downcase)
    end
  end
  
  # Iterates through all SUPPORTED_FRAMEWORKS and returns the symbolic name of the project application framework detected.  Otherwise, returns :Unknown
  def self.detect_framework_name
    SUPPORTED_FRAMEWORKS.each do |key, value|
      return key if value.call
    end
    :Unknown
  end
  
  # Same as detect_framework_name, but returns an instance of the specific AppFramework class.
  def self.detect_framework
    name = detect_framework_name
    self[name]
  end
  
  # Initializes, stores, and returns a singleton instance of the named AppFramework.
  #
  # == Parameters
  #
  # # +name+ - A symbolic name of a AppFramework subclass
  #
  # == Example
  #
  #   Spork::AppFramework[:Rails]
  def self.[](name)
    instances[name] ||= const_get(name).new
  end
  
  def self.short_name
    name.gsub('Spork::AppFramework::', '')
  end
  
  # If there is some stuff out of the box that the Spork can do to speed up tests without the test helper file being bootstrapped, this should return false.
  def bootstrap_required?
    entry_point.nil?
  end
  
  # Abstract: The path to the file that loads the project environment, ie config/environment.rb.  Returns nil if there is none.
  def entry_point
    raise NotImplementedError
  end
  
  def preload(&block)
    yield
  end
  
  def short_name
    self.class.short_name
  end
  
  protected
    def self.instances
      @instances ||= {}
    end
end

Spork::AppFramework.setup_autoload