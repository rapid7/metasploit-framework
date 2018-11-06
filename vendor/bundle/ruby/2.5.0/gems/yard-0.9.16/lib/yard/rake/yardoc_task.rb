# frozen_string_literal: true
require 'rake'
require 'rake/tasklib'

module YARD
  module Rake
    # The rake task to run {CLI::Yardoc} and generate documentation.
    class YardocTask < ::Rake::TaskLib
      # The name of the task
      # @return [String] the task name
      attr_accessor :name

      # Options to pass to {CLI::Yardoc}
      # @return [Array<String>] the options passed to the commandline utility
      attr_accessor :options

      # Options to pass to {CLI::Stats}
      # @return [Array<String>] the options passed to the stats utility
      attr_accessor :stats_options

      # The Ruby source files (and any extra documentation files separated by '-')
      # to process.
      # @example Task files assignment
      #   YARD::Rake::YardocTask.new do |t|
      #     t.files   = ['app/**/*.rb', 'lib/**/*.rb', '-', 'doc/FAQ.md', 'doc/Changes.md']
      #   end
      # @return [Array<String>] a list of files
      attr_accessor :files

      # Runs a +Proc+ before the task
      # @return [Proc] a proc to call before running the task
      attr_accessor :before

      # Runs a +Proc+ after the task
      # @return [Proc] a proc to call after running the task
      attr_accessor :after

      # @return [Verifier, Proc] an optional {Verifier} to run against all objects
      #   being generated. Any object that the verifier returns false for will be
      #   excluded from documentation. This attribute can also be a lambda.
      # @see Verifier
      attr_accessor :verifier

      # Creates a new task with name +name+.
      #
      # @param [String, Symbol] name the name of the rake task
      # @yield a block to allow any options to be modified on the task
      # @yieldparam [YardocTask] _self the task object to allow any parameters
      #   to be changed.
      def initialize(name = :yard)
        @name = name
        @options = []
        @stats_options = []
        @files = []

        yield self if block_given?
        self.options += ENV['OPTS'].split(/[ ,]/) if ENV['OPTS']
        self.files   += ENV['FILES'].split(/[ ,]/) if ENV['FILES']
        self.options << '--no-stats' unless stats_options.empty?

        define
      end

      protected

      # Defines the rake task
      # @return [void]
      def define
        desc "Generate YARD Documentation" unless ::Rake.application.last_description
        task(name) do
          before.call if before.is_a?(Proc)
          yardoc = YARD::CLI::Yardoc.new
          yardoc.options[:verifier] = verifier if verifier
          yardoc.run(*(options + files))
          YARD::CLI::Stats.run(*(stats_options + ['--use-cache'])) unless stats_options.empty?
          after.call if after.is_a?(Proc)
        end
      end
    end
  end
end
