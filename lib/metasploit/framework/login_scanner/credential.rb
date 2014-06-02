require 'active_model'

module Metasploit
  module Framework
    module LoginScanner

      # This class provides an in-memory representation of a conceptual Credential
      #
      # It contains the public, private, and realm if any.
      class Credential
        include ActiveModel::Validations

        # @!attribute paired
        #   @return [Boolean] Whether BOTH a public and private are required
        #     (defaults to `true`)
        attr_accessor :paired
        # @!attribute private
        #   The private credential component (e.g. username)
        #
        #   @return [String] if {#paired} is `true` or {#private} is `nil`
        #   @return [String, nil] if {#paired} is `false` or {#private} is not `nil`.
        attr_accessor :private
        # @!attribute public
        #   The public credential component (e.g. password)
        #
        #   @return [String] if {#paired} is `true` or {#public} is `nil`
        #   @return [String, nil] if {#paired} is `false` or {#public} is not `nil`.
        attr_accessor :public
        # @!attribute realm
        #   @return [String,nil] The realm credential component (e.g domain name)
        attr_accessor :realm

        validates :paired,
          inclusion: { in: [true, false] }

        # If we have no public we MUST have a private (e.g. SNMP Community String)
        validates :private,
          exclusion: { in: [nil] },
          if: "public.nil? or paired"

        # If we have no private we MUST have a public
        validates :public,
                  presence: true,
                  if: "private.nil? or paired"

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end

          self.paired = true if self.paired.nil?
        end

        def inspect
          "#<#{self.class} \"#{self.public}:#{self.private}@#{self.realm}\" >"
        end
      end
    end
  end
end
