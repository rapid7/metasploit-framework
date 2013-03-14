require 'rubygems'

SPEC_TMP_DIR = File.expand_path('tmp', File.dirname(__FILE__))
require 'spork'
require 'stringio'
require 'fileutils'
require 'rspec'

RSpec.configure do |config|
  config.before(:each) do
    $test_stdout = StringIO.new
    $test_stderr = StringIO.new
    @current_dir = nil
  end

  config.after(:each) do
    FileUtils.rm_rf(SPEC_TMP_DIR) if File.directory?(SPEC_TMP_DIR)
  end
end

def create_file(filename, contents)
  FileUtils.mkdir_p(SPEC_TMP_DIR) unless File.directory?(SPEC_TMP_DIR)

  in_current_dir do
    FileUtils.mkdir_p(File.dirname(filename))
    File.open(filename, 'wb') { |f| f << contents }
  end
end

def create_helper_file(test_framework = FakeFramework)
  create_file(test_framework.helper_file, "# stub spec helper file")
end

def in_current_dir(&block)
  Dir.chdir(current_dir, &block)
end

def current_dir
  @current_dir ||= SPEC_TMP_DIR
end

def change_current_dir(sub_path)
  @current_dir = File.expand_path(sub_path, SPEC_TMP_DIR)
end

def windows?
  ENV['OS'] == 'Windows_NT'
end


module RSpec
  module Matchers
    class IncludeAStringLike
      def initialize(substring_or_regex)
        case substring_or_regex
        when String
          @regex = Regexp.new(Regexp.escape(substring_or_regex))
        when Regexp
          @regex = substring_or_regex
        else
          raise ArgumentError, "don't know what to do with the #{substring_or_regex.class} you provided"
        end
      end

      def matches?(list_of_strings)
        @list_of_strings = list_of_strings
        @list_of_strings.any? { |s| s =~ @regex }
      end
      def failure_message
        "#{@list_of_strings.inspect} expected to include a string like #{@regex.inspect}"
      end
      def negative_failure_message
        "#{@list_of_strings.inspect} expected to not include a string like #{@regex.inspect}, but did"
      end
    end

    def include_a_string_like(substring_or_regex)
      IncludeAStringLike.new(substring_or_regex)
    end
  end
end

module Spork::TestIOStreams
  def self.included(klass)
    klass.send(:extend, ::Spork::TestIOStreams::ClassMethods)
  end

  def stderr
    self.class.stderr
  end

  def stdout
    self.class.stdout
  end

  module ClassMethods
    def stderr
      $test_stderr
    end

    def stdout
      $test_stdout
    end
  end
end

Dir.glob(File.dirname(__FILE__) + "/support/*.rb").each { |f| require(f) }
