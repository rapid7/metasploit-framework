require 'active_model'

module Metasploit
  module Framework
    # This class provides an in-memory representation of a conceptual Credential
    #
    # It contains the public, private, and realm if any.
    class Credential
      include ActiveModel::Validations

      # @!attribute paired
      #   @return [Boolean] Whether BOTH a public and private are required
      #     (defaults to `true`)
      attr_accessor :paired
      # @!attribute parent
      #   @return [Object] the parent object that had .to_credential called on it to create this object
      attr_accessor :parent
      # @!attribute private
      #   The private credential component (e.g. username)
      #
      #   @return [String] if {#paired} is `true` or {#private} is `nil`
      #   @return [String, nil] if {#paired} is `false` or {#private} is not `nil`.
      attr_accessor :private
      # @!attribute private_type
      #   The type of private credential this object represents, e.g. a
      #   password or an NTLM hash.
      #
      #   @return [String]
      attr_accessor :private_type
      # @!attribute public
      #   The public credential component (e.g. password)
      #
      #   @return [String] if {#paired} is `true` or {#public} is `nil`
      #   @return [String, nil] if {#paired} is `false` or {#public} is not `nil`.
      attr_accessor :public
      # @!attribute realm
      #   @return [String,nil] The realm credential component (e.g domain name)
      attr_accessor :realm
      # @!attribute realm
      #   @return [String,nil] The type of {#realm}
      attr_accessor :realm_key

      validates :paired,
        inclusion: { in: [true, false] }

      # If we have no public we MUST have a private (e.g. SNMP Community String)
      validates :private,
        exclusion: { in: [nil] },
        if: "public.nil? or paired"

      # These values should be #demodularized from subclasses of
      # `Metasploit::Credential::Private`
      validates :private_type,
        inclusion: { in: [ :password, :ntlm_hash, :postgres_md5, :ssh_key ] },
        if: "private_type.present?"

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
        "#<#{self.class} \"#{self}\" >"
      end

      def to_s
        if realm && realm_key == Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
          "#{self.realm}\\#{self.public}:#{self.private}"
        elsif self.private
          "#{self.public}:#{self.private}#{at_realm}"
        else
          self.public
        end
      end

      def ==(other)
        other.respond_to?(:public) && other.public == self.public &&
        other.respond_to?(:private) && other.private == self.private &&
        other.respond_to?(:realm) && other.realm == self.realm
      end

      def to_credential
        self.parent = self
        self        
      end

      # This method takes all of the attributes of the {Credential} and spits
      # them out in a hash compatible with the create_credential calls.
      #
      # @return [Hash] a hash compatible with #create_credential
      def to_h
        {
            private_data: private,
            private_type: private_type,
            username: public,
            realm_key: realm_key,
            realm_value: realm
        }
      end

      private

      def at_realm
        if self.realm.present?
          "@#{self.realm}"
        else
          ""
        end
      end
    end
  end
end
