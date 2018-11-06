# frozen_string_literal: true
require "rubygems"
begin
  require "rspec"
rescue LoadError
  require "spec"
end

begin
  require 'bundler/setup'
rescue LoadError
  nil # noop
end

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib', 'yard'))

unless defined?(HAVE_RIPPER)
  begin require 'ripper'; rescue LoadError; nil end
  HAVE_RIPPER = defined?(::Ripper) && !ENV['LEGACY'] ? true : false
  LEGACY_PARSER = !HAVE_RIPPER

  class YARD::Parser::SourceParser
    def self.parser_type; @parser_type == :ruby ? :ruby18 : @parser_type end
  end if ENV['LEGACY']
end

begin
  require 'coveralls'
  Coveralls.wear!
end if ENV['CI'] && HAVE_RIPPER

NAMED_OPTIONAL_ARGUMENTS = RUBY_VERSION >= '2.1.0'

def parse_file(file, thisfile = __FILE__, log_level = log.level, ext = '.rb.txt')
  Registry.clear
  path = File.join(File.dirname(thisfile), 'examples', file.to_s + ext)
  YARD::Parser::SourceParser.parse(path, [], log_level)
end

def described_in_docs(klass, meth, file = nil)
  YARD::Tags::Library.define_tag "RSpec Specification", :it, :with_raw_title_and_text

  # Parse the file (could be multiple files)
  if file
    filename = File.join(YARD::ROOT, file)
    YARD::Parser::SourceParser.new.parse(filename)
  else
    underscore = klass.class_name.gsub(/([a-z])([A-Z])/, '\1_\2').downcase.gsub('::', '/')
    $LOADED_FEATURES.find_all {|p| p.include? underscore }.each do |found_fname|
      next unless File.exist? found_fname
      YARD::Parser::SourceParser.new.parse(found_fname)
    end
  end

  # Get the object
  objname = klass.name + (meth[0, 1] == '#' ? meth : '::' + meth)
  obj = Registry.at(objname)
  raise "Cannot find object #{objname} described by spec." unless obj
  raise "#{obj.path} has no @it tags to spec." unless obj.has_tag? :it

  # Run examples
  describe(klass, meth) do
    obj.tags(:it).each do |it|
      path = File.relative_path(YARD::ROOT, obj.file)
      it(it.name + " (from #{path}:#{obj.line})") do
        begin
          eval(it.text)
        rescue => e
          e.set_backtrace(["#{path}:#{obj.line}:in @it tag specification"])
          raise e
        end
      end
    end
  end
end

def docspec(objname = self.class.description, klass = self.class.described_type)
  # Parse the file (could be multiple files)
  underscore = klass.class_name.gsub(/([a-z])([A-Z])/, '\1_\2').downcase.gsub('::', '/')
  $LOADED_FEATURES.find_all {|p| p.include? underscore }.each do |filename|
    filename = File.join(YARD::ROOT, filename)
    next unless File.exist? filename
    YARD::Parser::SourceParser.new.parse(filename)
  end

  # Get the object
  objname = klass.name + objname if objname =~ /^[^A-Z]/
  obj = Registry.at(objname)
  raise "Cannot find object #{objname} described by spec." unless obj
  raise "#{obj.path} has no @example tags to spec." unless obj.has_tag? :example

  # Run examples
  obj.tags(:example).each do |exs|
    exs.text.split(/\n/).each do |ex|
      begin
        hash = eval("{ #{ex} }")
        expect(hash.keys.first).to eq hash.values.first
      rescue => e
        raise e, "#{e.message}\nInvalid spec example in #{objname}:\n\n\t#{ex}\n"
      end
    end
  end
end

module Kernel
  require 'cgi'

  def p(*args)
    puts args.map {|arg| CGI.escapeHTML(arg.inspect) }.join("<br/>\n")
    args.first
  end

  def puts(str = '')
    STDOUT.puts str + "<br/>\n"
    str
  end
end if ENV['TM_APP_PATH']

RSpec.configure do |config|
  config.before(:each) { log.io = StringIO.new }

  # isolate environment of each test
  # any other global settings which might be modified by a test should also
  # be saved and restored here
  config.around(:each) do |example|
    saved_level = log.level
    example.run
    log.level = saved_level
  end

  # rspec-expectations config goes here. You can use an alternate
  # assertion/expectation library such as wrong or the stdlib/minitest
  # assertions if you prefer.
  config.expect_with :rspec do |expectations|
    # This option will default to `true` in RSpec 4. It makes the `description`
    # and `failure_message` of custom matchers include text for helper methods
    # defined using `chain`, e.g.:
    #     be_bigger_than(2).and_smaller_than(4).description
    #     # => "be bigger than 2 and smaller than 4"
    # ...rather than:
    #     # => "be bigger than 2"
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  # rspec-mocks config goes here. You can use an alternate test double
  # library (such as bogus or mocha) by changing the `mock_with` option here.
  config.mock_with :rspec do |mocks|
    # Prevents you from mocking or stubbing a method that does not exist on
    # a real object. This is generally recommended, and will default to
    # `true` in RSpec 4.
    # mocks.verify_partial_doubles = true # FIXME: Not yet working
  end

  # This option will default to `:apply_to_host_groups` in RSpec 4 (and will
  # have no way to turn it off -- the option exists only for backwards
  # compatibility in RSpec 3). It causes shared context metadata to be
  # inherited by the metadata hash of host groups and examples, rather than
  # triggering implicit auto-inclusion in groups with matching metadata.
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # This allows you to limit a spec run to individual examples or groups
  # you care about by tagging them with `:focus` metadata. When nothing
  # is tagged with `:focus`, all examples get run. RSpec also provides
  # aliases for `it`, `describe`, and `context` that include `:focus`
  # metadata: `fit`, `fdescribe` and `fcontext`, respectively.
  config.filter_run_when_matching :focus

  # Allows RSpec to persist some state between runs in order to support
  # the `--only-failures` and `--next-failure` CLI options. We recommend
  # you configure your source control system to ignore this file.
  config.example_status_persistence_file_path = "spec/examples.txt"

  # Limits the available syntax to the non-monkey patched syntax that is
  # recommended. For more details, see:
  #   - http://rspec.info/blog/2012/06/rspecs-new-expectation-syntax/
  #   - http://www.teaisaweso.me/blog/2013/05/27/rspecs-new-message-expectation-syntax/
  #   - http://rspec.info/blog/2014/05/notable-changes-in-rspec-3/#zero-monkey-patching-mode
  config.disable_monkey_patching!

  # This setting enables warnings. It's recommended, but in some cases may
  # be too noisy due to issues in dependencies.
  config.warnings = false

  # Many RSpec users commonly either run the entire suite or an individual
  # file, and it's useful to allow more verbose output when running an
  # individual spec file.
  if config.files_to_run.one?
    # Use the documentation formatter for detailed output,
    # unless a formatter has already been configured
    # (e.g. via a command-line flag).
    config.default_formatter = 'doc'
  end

  # Print the N slowest examples and example groups at the
  # end of the spec run, to help surface which specs are running
  # particularly slow.
  config.profile_examples = 5

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  # config.order = :random # FIXME: Not yet working

  # Seed global randomization in this process using the `--seed` CLI option.
  # Setting this allows you to use `--seed` to deterministically reproduce
  # test failures related to randomization by passing the same `--seed` value
  # as the one that triggered the failure.
  Kernel.srand config.seed
end

include YARD
