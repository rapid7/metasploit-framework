# -*- coding: binary -*-

#
# Infers runtime version metadata (the 'RuntimeVersions' target option) from a
# human-readable exploit target name.
#
# The 'RuntimeVersions' hash is keyed by runtime name (e.g. 'Windows',
# 'Python') and consumed by Msf::Module::VersionCompatibility to warn when a
# payload's minimum supported version is newer than the version a target
# provides.
#
# Only Windows inference is implemented today, but the registry below is the
# single extension point: supporting a new runtime (macOS, Linux, ...) is a
# matter of adding one Inferrer that knows its runtime key, which platforms it
# applies to, and how to turn a target name into a Rex::Version.
#
module Msf::Module::RuntimeVersionInference
  #
  # Describes how to infer a single runtime's version from a target name.
  #
  # @!attribute runtime
  #   @return [String] The 'RuntimeVersions' hash key this inferrer populates.
  # @!attribute platform_pattern
  #   @return [Regexp, nil] Matched against a target's declared platform names.
  #     When it matches none of them the inferrer is skipped; nil means the
  #     inferrer is not platform gated.
  # @!attribute resolver
  #   @return [#call] A callable taking the target name and returning a
  #     Rex::Version or nil.
  #
  Inferrer = Struct.new(:runtime, :platform_pattern, :resolver) do
    # Resolve the runtime version for the supplied target name.
    #
    # @param name [String] The exploit target name.
    # @return [Rex::Version, nil]
    def infer(name)
      resolver.call(name)
    end

    # Whether this inferrer applies to a target declaring the given platform
    # names. When the target declares no platform we fall back to name-based
    # inference (return true), and an inferrer with no platform_pattern is
    # always considered applicable.
    #
    # @param platform_names [Array<String>, nil] Lower-cased platform names.
    # @return [Boolean]
    def applicable_to_platforms?(platform_names)
      return true if platform_names.nil? || platform_names.empty?
      return true if platform_pattern.nil?

      platform_names.any? { |platform_name| platform_pattern.match?(platform_name) }
    end
  end

  # The ordered list of registered inferrers. Add new runtimes here.
  INFERRERS = [
    Inferrer.new('Windows', /win/i, ->(name) { Msf::WindowsVersion.from_target_name(name) })
  ].freeze

  module_function

  # Infer runtime versions for a target name.
  #
  # @param name [String] The exploit target name.
  # @param existing [Hash] Runtime versions already set (e.g. manually in module
  #   metadata). Runtimes present here are never overwritten.
  # @param platform_names [Array<String>, nil] The target's declared platform
  #   names (lower-cased), used to skip inferrers for other platforms. Nil when
  #   the target declares no platform.
  # @return [Hash] A hash of runtime name => Rex::Version for the runtimes that
  #   could be inferred. Empty when nothing could be inferred.
  def infer(name, existing: {}, platform_names: nil)
    inferred = {}

    INFERRERS.each do |inferrer|
      # Respect any explicitly supplied version for this runtime.
      next if existing.key?(inferrer.runtime)
      next unless inferrer.applicable_to_platforms?(platform_names)

      version = inferrer.infer(name)
      inferred[inferrer.runtime] = version unless version.nil?
    end

    inferred
  end
end
