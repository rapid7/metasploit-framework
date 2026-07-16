# frozen_string_literal: true

module Msf
  module Reporting
    # RSpec mixin giving a framework / in-tree library spec a fresh in-memory
    # +Msf::Reporting::Backends::InMemoryBackend+ as +reporter+ and a
    # +have_reported+ matcher for asserting on recorded calls.
    #
    # Test-only artifact: lives under +spec/support/reporting/+ and is NOT
    # shipped with the framework gem. Audience is framework and in-tree
    # library specs only; per-module specs and downstream gem consumers
    # are out of scope.
    #
    # @example
    #   require 'support/reporting/test_helper'
    #
    #   RSpec.describe SomeFrameworkLibraryClass do
    #     include Msf::Reporting::TestHelper
    #
    #     it 'reports the discovered host' do
    #       reporter.report_host(address: '192.0.2.10')
    #       expect(reporter).to have_reported(:host, address: '192.0.2.10')
    #     end
    #   end
    module TestHelper
      def self.included(base)
        base.let(:reporter) { Msf::Reporting::Backends::InMemoryBackend.new } if base.respond_to?(:let)
      end
    end
  end
end

if defined?(RSpec::Matchers)
  # @!method have_reported(entity_type, **expected_fields)
  #
  # Matches when the actual +InMemoryBackend+ has at least one recorded
  # call whose +entity_type+ equals +entity_type+ and whose +kwargs+
  # superset-match the provided +expected_fields+ (callers supply a
  # subset of fields).
  #
  # Modifiers:
  #   .exactly(n).time / .times → assert an exact match count.
  #   .at_least(n).time(s)      → assert minimum match count.
  #   .at_most(n).time(s)       → assert maximum match count.
  RSpec::Matchers.define :have_reported do |entity_type, **expected_fields|
    match do |reporter|
      @entity_type = entity_type
      @expected_fields = expected_fields
      @all_calls = reporter.respond_to?(:calls) ? reporter.calls : []
      @matching = @all_calls.select do |call|
        next false unless call[:entity_type] == entity_type

        expected_fields.all? { |k, v| call[:kwargs].key?(k) && call[:kwargs][k] == v }
      end

      if @exact_count
        @matching.size == @exact_count
      elsif @min_count
        @matching.size >= @min_count
      elsif @max_count
        @matching.size <= @max_count
      else
        @matching.any?
      end
    end

    chain :exactly do |n|
      @exact_count = n
    end

    chain :at_least do |n|
      @min_count = n
    end

    chain :at_most do |n|
      @max_count = n
    end

    # Sugar so the call reads naturally: `.exactly(1).time` /
    # `.exactly(2).times`. These chains carry no semantics on their own.
    chain(:time) {}
    chain(:times) {}

    failure_message do |_reporter|
      base = "expected reporter to have reported #{@entity_type.inspect}"
      base += " with fields #{@expected_fields.inspect}" unless @expected_fields.empty?
      base += " (matched #{@matching.size}, expected #{@exact_count})" if @exact_count
      base += "\nrecorded calls:\n  #{format_calls.join("\n  ")}"
      base
    end

    failure_message_when_negated do |_reporter|
      "expected reporter NOT to have reported #{@entity_type.inspect}" \
        "#{@expected_fields.empty? ? '' : " with fields #{@expected_fields.inspect}"}" \
        " but matched #{@matching.size} call(s)"
    end

    define_method(:format_calls) do
      @all_calls.map { |c| "#{c[:method]} #{c[:kwargs].inspect}" }
    end
  end
end
