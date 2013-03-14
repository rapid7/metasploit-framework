class Spork::TestFramework
  LOAD_PREFERENCE = ['RSpec', 'Cucumber']
  BOOTSTRAP_FILE = File.dirname(__FILE__) + "/../../assets/bootstrap.rb"

  @@supported_test_frameworks = []
  attr_reader :stdout, :stderr

  class FactoryException < Exception; end

  class NoFrameworksAvailable < FactoryException
    def message
      "I can\'t find any testing frameworks to use.  Are you running me from a project directory?"
    end
  end

  class FrameworkNotAvailable < FactoryException
    def initialize(framework)
      @framework = framework
    end

    def message
      "I can\'t find the file #{@framework.helper_file} for the #{@framework.short_name} testing framework.\nAre you running me from the project directory?"
    end
  end

  class NoFrameworkMatched < FactoryException
    def initialize(beginning_with)
      @beginning_with = beginning_with
    end

    def message
      "Couldn\'t find a supported test framework that begins with '#{@beginning_with}'"
    end
  end

  def initialize(stdout = STDOUT, stderr = STDERR)
    @stdout, @stderr = stdout, stderr
  end

  def self.factory(output = STDOUT, error = STDERR, beginning_with = nil)
    if beginning_with
      @klass = supported_test_frameworks(beginning_with).first
      raise(NoFrameworkMatched.new(beginning_with)) if @klass.nil?
      raise(FrameworkNotAvailable.new(@klass)) unless @klass.available?
    else
      @klass = available_test_frameworks.first
      raise(NoFrameworksAvailable.new) unless @klass
    end
    @klass.new(output, error)
  end

  def self.helper_file
    self::HELPER_FILE
  end

  def self.default_port
    (ENV["#{short_name.upcase}_DRB"] || self::DEFAULT_PORT).to_i
  end

  def self.short_name
    self.name.gsub('Spork::TestFramework::', '')
  end

  # Returns a list of all testing servers that have detected their testing framework being used in the project.
  def self.available_test_frameworks
    supported_test_frameworks.select { |s| s.available? }
  end

  # Returns a list of all servers that have been implemented (it keeps track of them automatically via Class.inherited)
  def self.supported_test_frameworks(starting_with = nil)
    @@supported_test_frameworks.sort! { |a,b| a.load_preference_index <=> b.load_preference_index }
    return @@supported_test_frameworks if starting_with.nil?
    @@supported_test_frameworks.select do |s|
      s.short_name.match(/^#{Regexp.escape(starting_with)}/i)
    end
  end

  def short_name
    self.class.short_name
  end

  def helper_file
    self.class.helper_file
  end

  # Detects if the test helper has been bootstrapped.
  def bootstrapped?
    File.read(helper_file).include?("Spork.prefork")
  end

  # Bootstraps the current test helper file by prepending a Spork.prefork and Spork.each_run block at the beginning.
  def bootstrap
    if bootstrapped?
      stderr.puts "Already bootstrapped!"
      return
    end
    stderr.puts "Bootstrapping #{helper_file}."
    contents = File.read(helper_file)
    bootstrap_code = File.read(BOOTSTRAP_FILE)
    File.open(helper_file, "wb") do |f|
      f.puts bootstrap_code
      f.puts contents
    end

    stderr.puts "Done. Edit #{helper_file} now with your favorite text editor and follow the instructions."
    true
  end

  # Returns true if the testing frameworks helper file exists.  Override if this is not sufficient to detect your testing framework.
  def self.available?
    File.exist?(helper_file)
  end

  # Used to specify
  def self.load_preference_index
    LOAD_PREFERENCE.index(short_name) || LOAD_PREFERENCE.length
  end

  def preload
    Spork.exec_prefork do
      if not bootstrapped?
        stderr.puts "#{helper_file} has not been bootstrapped.  Run spork --bootstrap to do so."
        stderr.flush

        if framework.bootstrap_required?
          stderr.puts "I can't do anything for you by default for the framework you're using: #{framework.short_name}.\nYou must bootstrap #{helper_file} to continue."
          stderr.flush
          return false
        else
          load(framework.entry_point)
        end
      end

      framework.preload do
        if bootstrapped?
          stderr.puts "Loading Spork.prefork block..."
          stderr.flush
          load(helper_file)
        end
      end
    end
    true
  end

  def run_tests(argv, stderr, stdout)
    raise NotImplementedError
  end

  def entry_point
    bootstrapped? ? helper_file : framework.entry_point
  end

  def default_port
    self.class.default_port
  end

  protected
    def self.inherited(subclass)
      @@supported_test_frameworks << subclass
    end

    def framework
      @framework ||= Spork::AppFramework.detect_framework
    end
end

Spork.detect_and_require('spork/test_framework/*.rb')
