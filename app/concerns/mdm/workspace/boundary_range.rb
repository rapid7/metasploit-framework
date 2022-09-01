module Mdm::Workspace::BoundaryRange
  extend ActiveSupport::Concern

  included do
    #
    # Validations
    #

    validate :boundary_must_be_ip_range

    #
    # Instance Methods
    #

    # If {#limit_to_network} is disabled, this will always return `true`.
    # Otherwise, return `true` only if all of the given IPs are within the
    # project {#boundary boundaries}.

    #
    # @param ips [String] IP range(s)
    # @return [true] if actions on ips are allowed.
    # @return [false] if actions are not allowed on ips.
    def allow_actions_on?(ips)
      return true unless limit_to_network
      return true unless boundary
      return true if boundary.empty?
      boundaries = Shellwords.split(boundary)
      return true if boundaries.empty? # It's okay if there is no boundary range after all
      given_range = Rex::Socket::RangeWalker.new(ips)
      return false unless given_range # Can't do things to nonexistant IPs
      allowed = false
      boundaries.each do |boundary_range|
        ok_range = Rex::Socket::RangeWalker.new(boundary)
        allowed  = true if ok_range.include_range? given_range
      end
      return allowed
    end

    # Validates that {#boundary} is {#valid_ip_or_range? a valid IP address or
    # IP address range}. Due to this not being tested before it was moved here
    # from Mdm, the default workspace does not validate. We always validate boundaries
    # and a workspace may have a blank default boundary.
    #
    # @return [void]
    def boundary_must_be_ip_range
      unless boundary.blank?
        begin
          boundaries = Shellwords.split(boundary)
        rescue ArgumentError
          boundaries = []
        end

        boundaries.each do |range|
          unless valid_ip_or_range?(range)
            errors.add(:boundary, "must be a valid IP range")
          end
        end
      end
    end

    # Returns an array of addresses ranges
    #
    # @return [Array<String>]
    def addresses
      (boundary || "").split("\n")
    end

    private

    # Returns whether `string` is a valid IP address or IP address range.
    #
    # @return [true] if valid IP address or IP address range.
    # @return [false] otherwise.
    def valid_ip_or_range?(string)
      range = Rex::Socket::RangeWalker.new(string)
      range && range.ranges && range.ranges.any?
    end

  end


end
