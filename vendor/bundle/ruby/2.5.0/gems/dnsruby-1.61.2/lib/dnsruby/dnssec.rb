# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License f181or the specific language governing permissions and
# limitations under the License.
# ++
require 'digest/sha2'
require 'net/ftp'
require 'dnsruby/key_cache'
require 'dnsruby/single_verifier'
module Dnsruby

  #  RFC4033, section 7
  #    "There is one more step that a security-aware stub resolver can take
  #    if, for whatever reason, it is not able to establish a useful trust
  #    relationship with the recursive name servers that it uses: it can
  #    perform its own signature validation by setting the Checking Disabled
  #    (CD) bit in its query messages.  A validating stub resolver is thus
  #    able to treat the DNSSEC signatures as trust relationships between
  #    the zone administrators and the stub resolver itself. "
  # 
  #  Dnsruby is configured to validate responses by default. However, it is not
  #  configured with any trusted keys by default. Applications may use the
  #  verify() method to perform verification with of RRSets of Messages with
  #  given keys. Alternatively, trusted keys may be added to this class (either
  #  directly, or by loading the IANA TAR or the DLV ISC ZSK). Validation will then
  #  be performed from these keys (or the DLV registry, if configured). Negative
  #  and positive responses are validation.
  # 
  #  Messages are tagged with the current security_level (Message::SecurityLevel).
  #  UNCHECKED means Dnsruby has not attempted to validate the response.
  #  BOGUS means the response has been checked, and is bogus.
  #  INSECURE means the response has been validated to be insecure (e.g. in an unsigned zone)
  #  SECURE means that the response has been verfied to be correct.
  # 
  #  Several validators are provided, with each maintaining its own cache of trusted keys.
  #  If validators are added or removed, the caches of the other validators are not affected.
  class Dnssec
    #  A class to cache trusted keys


    class ValidationPolicy
      #  @TODO@ Could do this by getting client to add verifiers in the order they
      #  want them to be used. Could then dispense with all this logic
      #  Note that any DLV registries which have been configured will only be tried
      #  after both the root and any local trust anchors (RFC 5074 section 5)

      # * Always use the root and ignore local trust anchors.
      ALWAYS_ROOT_ONLY = 1
      # * Use the root if successful, otherwise try local anchors.
      ROOT_THEN_LOCAL_ANCHORS = 2
      # * Use local trust anchors if available, otherwise use root.
      LOCAL_ANCHORS_THEN_ROOT = 3
      # * Always use local trust anchors and ignore the root.
      ALWAYS_LOCAL_ANCHORS_ONLY = 4
    end
    @@validation_policy = ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT

    def Dnssec.validation_policy=(p)
      if ((p >= ValidationPolicy::ALWAYS_ROOT_ONLY) && (p <= ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY))
        @@validation_policy = p
        #  @TODO@ Should we be clearing the trusted keys now?
      end
    end
    def Dnssec.validation_policy
      @@validation_policy
    end

    @@root_verifier = SingleVerifier.new(SingleVerifier::VerifierType::ROOT)

    #  #NOTE# You may wish to import these via a secure channel yourself, if
    #  using Dnsruby for validation.
    @@root_key = RR.create(". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5")
    @@root_verifier.add_root_ds(@@root_key)

    @@root_key_new = RR.create(". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
    @@root_verifier.add_root_ds(@@root_key_new)

    @@dlv_verifier = SingleVerifier.new(SingleVerifier::VerifierType::DLV)

    #  @TODO@ Could add a new one of these for each anchor.
    @@anchor_verifier = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)


    #  Add a trusted Key Signing Key for the ISC DLV registry.
    def Dnssec.add_dlv_key(dlv_key)
      @@dlv_verifier.add_dlv_key(dlv_key)
    end
    #  Add a new trust anchor
    def Dnssec.add_trust_anchor(t)
      #  @TODO@ Create a new verifier?
      @@anchor_verifier.add_trust_anchor(t)
    end
    #  Add the trusted key with the given expiration time
    def self.add_trust_anchor_with_expiration(k, expiration)
      #  Create a new verifier?
      @@anchor_verifier.add_trust_anchor_with_expiration(k, expiration)
    end
    #  Remove the trusted key
    def Dnssec.remove_trust_anchor(t)
      @@anchor_verifier.remove_trust_anchor(t)
    end
    #  Wipes the cache of trusted keys
    def self.clear_trust_anchors
      @@anchor_verifier.clear_trust_anchors
    end

    def self.trust_anchors
      return @@anchor_verifier.trust_anchors
    end

    def self.clear_trusted_keys
      [@@anchor_verifier, @@root_verifier, @@dlv_verifier].each {|v|
        v.clear_trusted_keys
      }
    end

    def self.reset
      @@validation_policy = ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT
      @@root_verifier = SingleVerifier.new(SingleVerifier::VerifierType::ROOT)
      @@root_verifier.add_root_ds(@@root_key)

      @@dlv_verifier = SingleVerifier.new(SingleVerifier::VerifierType::DLV)

      #  @TODO@ Could add a new one of these for each anchor.
      @@anchor_verifier = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)
      @@do_validation_with_recursor = true # Many nameservers don't handle DNSSEC correctly yet
      @@default_resolver = Resolver.new
    end

    def self.set_hints(hints)
      @@root_verifier.set_hints(hints)
      @@anchor_verifier.set_hints(hints)
    end

    def self.no_keys?
      no_keys = true
      [@@anchor_verifier, @@root_verifier, @@dlv_verifier].each {|v|
        if (v.trusted_keys.length() > 0 ||
              v.trust_anchors.length() > 0)
          no_keys = false
        end
      }
      return no_keys
    end

    @@do_validation_with_recursor = true # Many nameservers don't handle DNSSEC correctly yet
    @@default_resolver = Resolver.new
    #  This method defines the choice of Resolver or Recursor, when the validator
    #  is checking responses.
    #  If set to true, then a Recursor will be used to query for the DNSSEC records.
    #  Otherwise, the default system resolver will be used.
    def self.do_validation_with_recursor(on)
      @@do_validation_with_recursor = on
    end
    def self.do_validation_with_recursor?
      return @@do_validation_with_recursor
    end
    #  This method overrides the system default resolver configuration for validation
    #  If default_resolver is set, then it will be used to follow the chain of trust.
    #  If it is not, then the default system resolver will be used (unless do_validation_with_recursor
    #  is set.
    def self.default_resolver=(res)
      @@default_resolver = res
    end
    def self.default_resolver
      return @@default_resolver
    end

    #  Returns true for secure/insecure, false otherwise
    #  This method will set the security_level on msg to the appropriate value.
    #  Could be : secure, insecure, bogus or indeterminate
    #  If an error is encountered during verification, then the thrown exception
    #  will define the error.
    def self.validate(msg)
      query = Message.new()
      query.header.cd=true
      return self.validate_with_query(query, msg)
    end

    def self.validate_with_query(query, msg)
      if (!msg)
        return false
      end
      #  First, just check there is something to validate!
      found_sigs = false
      msg.each_resource {|rr|
        if (rr.type == Types::RRSIG)
          found_sigs = true
        end
      }
      if (found_sigs)
        begin
          if (verify(msg))
            msg.security_level = Message::SecurityLevel.SECURE
            return true
          end
        rescue VerifyError => e
          msg.security_error = e
          msg.security_level = Message::SecurityLevel.BOGUS
        end
      end

      #  SHOULD ALWAYS VERIFY DNSSEC-SIGNED RESPONSES?
      #  Yes - if a trust anchor is configured. Otherwise, act on CD bit (in query)
      TheLog.debug("Checking whether to validate, query.cd = #{query.header.cd}")
      if (((@@validation_policy > ValidationPolicy::ALWAYS_ROOT_ONLY) && (self.trust_anchors().length > 0)) ||
            #  Check query here, and validate if CD is true
          ((query.header.cd == true))) # && (query.do_validation)))
        TheLog.debug("Starting validation")

        #  Validate!
        #  Need to think about trapping/storing exceptions and security_levels here
        last_error = ""
        last_level = Message::SecurityLevel.BOGUS
        last_error_level = Message::SecurityLevel.BOGUS
        if (@@validation_policy == ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_anchors(m, q)}, msg, query)
        elsif (@@validation_policy == ValidationPolicy::ALWAYS_ROOT_ONLY)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_root(m, q)}, msg, query)
        elsif (@@validation_policy == ValidationPolicy::LOCAL_ANCHORS_THEN_ROOT)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_anchors(m, q)}, msg, query)
          if (last_level != Message::SecurityLevel.SECURE)
            last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
              Proc.new{|m, q| validate_with_root(m, q)}, msg, query)
          end
        elsif (@@validation_policy == ValidationPolicy::ROOT_THEN_LOCAL_ANCHORS)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_root(m, q)}, msg, query)
          if (last_level != Message::SecurityLevel.SECURE)
            last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
              Proc.new{|m, q| validate_with_anchors(m, q)}, msg, query)
          end
        end
        if (last_level != Message::SecurityLevel.SECURE && last_level != Message::SecurityLevel.BOGUS)
          last_level, last_error, last_error_level = try_validation(last_level, last_error, last_error_level,
            Proc.new{|m, q| validate_with_dlv(m, q)}, msg, query)
        end
        #  Set the message security level!
        msg.security_level = last_level
        msg.security_error = last_error
        if (last_error && last_error.index("ification error"))
          msg.security_level = Message::SecurityLevel.BOGUS
        end
        raise VerifyError.new(last_error) if (last_level < 0)
        return (msg.security_level.code > Message::SecurityLevel::UNCHECKED)
      end
      msg.security_level = Message::SecurityLevel.UNCHECKED
      return true
    end

    def self.try_validation(last_level, last_error, last_error_level, proc, msg, query)   # :nodoc:
      begin
        proc.call(msg, query)
        last_level = Message::SecurityLevel.new([msg.security_level.code, last_level.code].max)
      rescue VerifyError => e
        if (last_error_level < last_level)
          last_error = e.to_s
          last_error_level = last_level
        end
      end
      return last_level, last_error, last_error_level
    end

    def self.validate_with_anchors(msg, query)
      return @@anchor_verifier.validate(msg, query)
    end

    def self.validate_with_root(msg, query)
      return @@root_verifier.validate(msg, query)
    end

    def self.validate_with_dlv(msg, query)
      return @@dlv_verifier.validate(msg, query)
    end

    def self.verify(msg, keys=nil)
      begin
        return true if @@anchor_verifier.verify(msg, keys)
      rescue VerifyError
        begin
          return true if @@root_verifier.verify(msg, keys)
        rescue VerifyError
          return true if @@dlv_verifier.verify(msg, keys) # Will carry error to client
        end
      end
    end

    def self.anchor_verifier
      return @@anchor_verifier
    end
    def self.dlv_verifier
      return @@dlv_verifier
    end
    def self.root_verifier
      return @@root_verifier
    end




    def self.verify_rrset(rrset, keys = nil)
      return ((@@anchor_verifier.verify_rrset(rrset, keys) ||
            @@root_verifier.verify_rrset(rrset, keys) ||
            @@dlv_verifier.verify_rrset(rrset, keys)))
    end
  end
end
