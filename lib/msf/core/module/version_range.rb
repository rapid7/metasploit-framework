# -*- coding: binary -*-

require 'rex/version'

#
# Provides a wrapper around a minimum and maximum version range.
# Both minimum and maximum are optional:
# - When no maximum is set, all versions >= min are considered within range.
# - When no minimum is set, all versions <= max are considered within range.
# - At least one of min or max must be provided.
#
class Msf::Module::VersionRange

  def initialize(min: nil, max: nil)
    raise "Improper argument(s) supplied to #{self.class}" if min.nil? && max.nil?
    raise "Improper argument(s) supplied to #{self.class}" unless min.nil? || valid_version_value?(min)
    raise "Improper argument(s) supplied to #{self.class}" unless max.nil? || valid_version_value?(max)

    self.min = min.nil? ? nil : to_version(min)
    self.max = max.nil? ? nil : to_version(max)
  end

  # Check whether a value is acceptable as a version argument.
  # Rex::Version is quite funky:
  #   Rex::Version.new(nil).to_s -> "0"
  #   Rex::Version.new('nil') raises ArgumentError
  # So we must guard against nil and non-numeric strings before creating Rex::Version.
  #
  # @param value [String, Integer, Rex::Version, nil] The value to check.
  # @return [Boolean]
  def self.valid_version_value?(value)
    return false if value.nil?
    return true if value.is_a?(Rex::Version)
    return true if value.is_a?(Integer)

    return false unless value.is_a?(String)
    return false if value.empty?

    begin
      Rex::Version.new(value)
      true
    rescue ArgumentError
      false
    end
  end

  # Does this version range contain the specified version?
  # A version is contained if it is >= min and, if a max is defined, <= max.
  #
  # @param version [String, Integer, Rex::Version] The version to check.
  # @return [Boolean, nil] true/false, or nil if the version value is invalid.
  def contains?(version)
    return nil unless valid_version_value?(version)

    ver = to_version(version)

    # If we don't have a minimum version defined, all versions <= max are affected.
    return ver <= max if min.nil?

    # If we don't have a maximum version defined, all versions >= min are OK.
    return ver >= min if max.nil?

    ver.between?(min, max)
  end

  # Normalize a value to Rex::Version.
  #
  # @param value [String, Integer, Rex::Version] The version to normalize.
  # @return [Rex::Version]
  def self.to_version(value)
    value.is_a?(Rex::Version) ? value : Rex::Version.new(value.to_s)
  end

  # @return [Rex::Version, nil] The minimum version (inclusive), or nil for unbounded.
  attr_accessor :min

  # @return [Rex::Version, nil] The maximum version (inclusive), or nil for unbounded.
  attr_accessor :max

  private

  def to_version(value)
    self.class.to_version(value)
  end

  def valid_version_value?(value)
    self.class.valid_version_value?(value)
  end

end
