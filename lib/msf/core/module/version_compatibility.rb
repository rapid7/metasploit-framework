# -*- coding: binary -*-

require 'rex/version'

#
# Provides version compatibility checks between exploit targets and payloads.
#
module Msf::Module::VersionCompatibility
  # Check version compatibility between a payload and the current exploit target.
  #
  # A payload declares its supported versions as a Hash of runtime name to an Array of
  # VersionRange objects (SupportedVersions). A target version is considered compatible
  # when it falls within at least one of the declared ranges for that runtime.
  #
  # @param payload_instance [Msf::Payload] A payload module instance.
  # @return [Array<String>] An array of warning strings. Empty means the payload is compatible.
  def version_compatibility_warnings(payload_instance)
    warnings = []

    target_versions = current_target_runtime_versions
    return warnings unless target_versions.is_a?(Hash) && !target_versions.empty?

    supported = payload_instance.supported_versions
    return warnings unless supported.is_a?(Hash) && !supported.empty?

    supported.each do |runtime, ranges|
      next unless target_versions.key?(runtime)
      next unless ranges.is_a?(Array) && !ranges.empty?

      target_ver = to_version(target_versions[runtime])

      # The target is compatible if it falls within any of the declared ranges.
      next if ranges.any? { |range| range.contains?(target_ver) }

      # No range matched - build a helpful warning using the lowest minimum across all ranges.
      lowest_min = ranges.map(&:min).min
      required_name = human_readable_version_string(runtime, lowest_min)
      target_name = human_readable_version_string(runtime, target_ver)
      warnings << "Payload requires #{runtime} version within a supported range (minimum #{required_name}), but the target provides #{target_name}"
    end

    warnings
  end

  private

  # Normalize a value to Rex::Version
  #
  # @param value [String, Rex::Version] The version to normalize.
  # @return [Rex::Version]
  def to_version(value)
    value.is_a?(Rex::Version) ? value : Rex::Version.new(value.to_s)
  end

  # Map a runtime (Windows, Python etc.) and a version to a human-readable string.
  # For example 'Windows', '5.1.2600.2' would get mapped to 'Windows XP Service Pack 2 (5.1.2600.2)'
  #
  # @param runtime [String] The runtime key (e.g., 'Windows', 'Python').
  # @param version [Rex::Version] The version to look up.
  # @return [String] A human-readable string
  def human_readable_version_string(runtime, version)
    case runtime
    when 'Windows'
      name = windows_version_name(version)
      return "#{name} (#{version})" if name
    end

    "#{runtime} (#{version})"
  end

  # Look up a Windows version's human-readable name from the WindowsVersion mappings.
  #
  # @param version [Rex::Version] The version to look up.
  # @return [String, nil] The friendly name, or nil if not found.
  def windows_version_name(version)
    [
      { klass: Msf::WindowsVersion::WorkstationSpecificVersions, mapping: Msf::WindowsVersion::WorkstationNameMapping },
      { klass: Msf::WindowsVersion::ServerSpecificVersions, mapping: Msf::WindowsVersion::ServerNameMapping }
    ].each do |h|
      h[:klass].constants.each do |const|
        return h[:mapping][const] if h[:klass].const_get(const) == version
      end
    end

    nil
  end

  # Get the lowest runtime version requirements from an array of targets.
  #
  # @param targets [Array<Msf::Target>] The array of targets to query over.
  # @return [Hash] The RuntimeVersions hash from the targets array.
  def lowest_runtime_versions_from_targets(targets)
    lowest_versions = {}
    targets.each do |t|
      versions = t.opts['RuntimeVersions']
      next unless versions.is_a?(Hash)

      versions.each do |runtime, version|
        ver = to_version(version)
        if lowest_versions[runtime].nil? || ver < lowest_versions[runtime]
          lowest_versions[runtime] = ver
        end
      end
    end

    lowest_versions
  end

  # Retrieve RuntimeVersions from the currently selected target.
  # When the Automatic target is selected, the lowest supported version of each defined
  # runtime (Windows, Python, etc.) is returned instead.
  #
  # @return [Hash, nil] The RuntimeVersions hash from the active target, or nil.
  def current_target_runtime_versions
    return nil unless respond_to?(:target) && target

    target_versions = target.opts['RuntimeVersions']
    if target_versions.is_a?(Hash) && !target_versions.empty?
      return target_versions
    end

    is_auto_target = target.opts['auto']
    return nil unless is_auto_target

    return nil unless respond_to?(:targets) && targets.is_a?(Array)

    lowest_versions = lowest_runtime_versions_from_targets(targets)
    lowest_versions.any? ? lowest_versions : nil
  end
end
