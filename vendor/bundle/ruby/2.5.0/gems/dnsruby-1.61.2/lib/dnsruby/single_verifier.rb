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
# See the License for the specific language governing permissions and
# limitations under the License.
# ++


# This class does verification/validation from a single point - signed root,
# DLV, trust anchors. Dnssec controls a set of these to perform validation for
# the client.
# This class should only be used by Dnsruby
module Dnsruby
  class SingleVerifier # :nodoc: all
    class VerifierType
      ROOT = 0
      ANCHOR = 1
      DLV = 2
    end
    def initialize(vtype)
      @verifier_type = vtype
      @added_dlv_key = false
      #  The DNSKEY RRs for the signed root (when it exists)
      @root_anchors = KeyCache.new

      #  The set of trust anchors.
      #  If the root is unsigned, then these must be initialised with at least
      #  one trusted key by the client application, if verification is to be performed.
      @trust_anchors = KeyCache.new

      @dlv_registries = []

      #  The set of keys which are trusted.
      @trusted_keys = KeyCache.new

      #  The set of keys which have been indicated by a DS RRSet which has been
      #  signed by a trusted key. Although we have not yet located these keys, we
      #  have the details (tag and digest) which can identify the keys when we
      #  see them. At that point, they will be added to our trusted keys.
      @discovered_ds_store = []
      #  The configured_ds_store is the set of DS records which have been configured
      #  by the client as trust anchors. Use Dnssec#add_trust_anchor to add these
      @configured_ds_store = []
    end

    def set_hints(hints)
      @@hints = hints
    end

    def get_recursor
      if (!defined?@@recursor)
        if (defined?@@hints)
          Recursor.set_hints(@@hints, Resolver.new)
          @@recursor = Recursor.new()
        else
          @@recursor = Recursor.new
        end
      end
      @@recursor.dnssec = true
      return @@recursor
    end

    def get_dlv_resolver # :nodoc:
      #       if (Dnssec.do_validation_with_recursor?)
      #         return Recursor.new
      #       else
      resolver = nil
      if (Dnssec.default_resolver)
        resolver = Dnssec.default_resolver
      else
        resolver = Resolver.new
      end
      #       end
      resolver.dnssec = true
      return resolver
    end
    def add_dlv_key(key)
      #  Is this a ZSK or a KSK?
      #  If it is a KSK, then get the ZSK from the zone
      if (key.sep_key?)
        get_dlv_key(key)
      end
    end
    def get_dlv_key(ksk) # :nodoc:
      #  Using the KSK, get the ZSK for the DLV registry
      if (!@res && (@verifier_type == VerifierType::DLV))
        @res = get_dlv_resolver
      end
      #       print "Sending query : res.dnssec = #{@res.dnssec}"
      ret = nil
      begin
        ret = @res.query_no_validation_or_recursion("dlv.isc.org.", Types.DNSKEY)
        if (!ret)
          raise ResolvError.new("Couldn't get response from Recursor")
        end
      rescue ResolvError => e
        #         print "ERROR - Couldn't find the DLV key\n"
        TheLog.error("Couldn't find the DLV key\n")
        return
      end
      key_rrset = ret.answer.rrset("dlv.isc.org", Types.DNSKEY)
      begin
        verify(key_rrset, ksk)
        add_trusted_key(key_rrset)
        #         print "Successfully added DLV key\n"
        TheLog.info("Successfully added DLV key")
        @added_dlv_key = true
      rescue VerifyError => e
        #         print "Error verifying DLV key : #{e}\n"
        TheLog.error("Error verifying DLV key : #{e}")
      end
    end
    def add_trust_anchor(t)
      add_trust_anchor_with_expiration(t, Time.utc(2035,"jan",1,20,15,1).to_i)
    end
    #  Add the
    def add_trust_anchor_with_expiration(k, expiration)
      if (k.type == Types.DNSKEY)
        #         k.flags = k.flags | RR::IN::DNSKEY::SEP_KEY
        @trust_anchors.add_key_with_expiration(k, expiration)
        #         print "Adding trust anchor for #{k.name}\n"
        TheLog.info("Adding trust anchor for #{k.name}")
      elsif ((k.type == Types.DS) || ((k.type == Types.DLV) && (@verifier_type == VerifierType::DLV)))
        @configured_ds_store.push(k)
      end
    end

    def remove_trust_anchor(t)
      @trust_anchors.delete(t)
    end
    #  Wipes the cache of trusted keys
    def clear_trust_anchors
      @trust_anchors = KeyCache.new
    end

    def trust_anchors
      return @trust_anchors.keys + @configured_ds_store
    end

    #  Check that the RRSet and RRSIG record are compatible
    def check_rr_data(rrset, sigrec)#:nodoc: all
      # Each RR MUST have the same owner name as the RRSIG RR;
      if (rrset.name.canonical != sigrec.name.canonical)
        raise VerifyError.new("RRSET should have same owner name as RRSIG for verification (rrsert=#{rrset.name}, sigrec=#{sigrec.name}")
      end

      # Each RR MUST have the same class as the RRSIG RR;
      if (rrset.klass != sigrec.klass)
        raise VerifyError.new("RRSET should have same DNS class as RRSIG for verification")
      end

      # Each RR in the RRset MUST have the RR type listed in the
      # RRSIG RR's Type Covered field;
      if (rrset.type != sigrec.type_covered)
        raise VerifyError.new("RRSET should have same type as RRSIG for verification")
      end

      #       #Each RR in the RRset MUST have the TTL listed in the
      #       #RRSIG Original TTL Field;
      #       if (rrset.ttl  != sigrec.original_ttl)
      #         raise VerifyError.new("RRSET should have same ttl as RRSIG original_ttl for verification (should be #{sigrec.original_ttl} but was #{rrset.ttl}")
      #       end

      #  Now check that we are in the validity period for the RRSIG
      now = Time.now.to_i
      if ((sigrec.expiration < now) || (sigrec.inception > now))
        raise VerifyError.new("Signature record not in validity period")
      end
    end

    #  Add the specified keys to the trusted key cache.
    #  k can be a KeyCache, or an RRSet of DNSKEYs.
    def add_trusted_key(k)
      @trusted_keys.add(k)
    end

    def add_root_ds(ds)
      @configured_ds_store.push(ds)
    end

    #  Wipes the cache of trusted keys
    def clear_trusted_keys
      @trusted_keys = KeyCache.new
      @res = nil
      @discovered_ds_store = []
      @configured_ds_store = []
    end

    def trusted_keys
      discovered_ds = []
      @discovered_ds_store.each {|rrset|
        rrset.rrs.each {|rr|
          discovered_ds.push(rr)
        }
      }
      return @trusted_keys.keys + @configured_ds_store + discovered_ds
    end

    #  Check that the key fits a signed DS record key details
    #  If so, then add the key to the trusted keys
    def check_ds(key, ds_rrset)#:nodoc: all
      expiration = 0
      found = false
      ds_rrset.sigs.each { |sig|
        if ((sig.type_covered == Types.DS) || ((sig.type_covered == Types.DLV)&& (@verifier_type==VerifierType::DLV)))
          if (sig.inception <= Time.now.to_i)
            #  Check sig.expiration, sig.algorithm
            if (sig.expiration > expiration)
              expiration = sig.expiration
            end
          end
        end
      }
      if (expiration > 0)
        ds_rrset.rrs.each { |ds|
          if ((ds.type === Types.DS) || ((ds.type == Types.DLV) && (@verifier_type == VerifierType::DLV)))
            if (ds.check_key(key))
              @trusted_keys.add_key_with_expiration(key, expiration)
              found = true
            end
          end
        }
      end
      return found
    end

    #  Verify the specified message (or RRSet) using the set of trusted keys.
    #  If keys is a DNSKEY, or an Array or RRSet of DNSKEYs, then keys
    #  is added to the set of trusted keys before the message (or RRSet) is
    #  verified.
    # 
    #  If msg is a Dnsruby::Message, then any signed DNSKEY or DS RRSets are
    #  processed first, and any new keys are added to the trusted key set
    #  before the other RRSets are checked.
    # 
    #  msg can be a Dnsruby::Message or Dnsruby::RRSet.
    #  keys may be nil, or a KeyCache or an RRSet of Dnsruby::RR::DNSKEY
    # 
    #  Returns true if the message verifies OK, and false otherwise.
    def verify(msg, keys = nil)
      if (msg.kind_of?RRSet)
        if (msg.type == Types.DNSKEY)
          return verify_key_rrset(msg, keys)
        end
        if ((msg.type == Types.DS) || (msg.type == Types.DLV))
          return verify_ds_rrset(msg, keys)

        end
        return verify_rrset(msg, keys)
      end
      #  Use the set of trusted keys to check any RRSets we can, ideally
      #  those of other DNSKEY RRSets first. Then, see if we can use any of the
      #  new total set of keys to check the rest of the rrsets.
      #  Return true if we can verify the whole message.

      msg.each_section do |section|
        #         print "Checking section : #{section}\n"
        ds_rrsets = section.rrsets(Types.DS)
        if ((!ds_rrsets || ds_rrsets.length == 0) && (@verifier_type == VerifierType::DLV))
          ds_rrsets = section.rrsets(Types.DLV)
        end
        ds_rrsets.each {|ds_rrset|
          if ((ds_rrset && ds_rrset.rrs.length > 0) && !verify_ds_rrset(ds_rrset, keys, msg))
            raise VerifyError.new("Failed to verify DS RRSet")
            #             return false
          end
        }

        key_rrsets = section.rrsets(Types.DNSKEY)
        key_rrsets.each {|key_rrset|
          if ((key_rrset && key_rrset.rrs.length > 0) && !verify_key_rrset(key_rrset, keys))
            raise VerifyError.new("Failed to verify DNSKEY RRSet")
            #             return false
          end
        }
      end

      verify_nsecs(msg)

      #  Then, look through all the remaining RRSets, and verify them all (unless not necessary).
      msg.section_rrsets.each do |section, rrsets|
        rrsets.each do |rrset|
          #  If delegation NS or glue AAAA/A, then don't expect RRSIG.
          #  Otherwise, expect RRSIG and fail verification if RRSIG is not present

          if ((section == "authority") && (rrset.type == Types.NS))
            #  Check for delegation
            dsrrset = msg.authority.rrsets('DS')[0]
            if ((msg.answer.size == 0) && (!dsrrset) && (rrset.type == Types.NS)) # (isDelegation)
              #  Now check NSEC(3) records for absence of DS and SOA
              nsec = msg.authority.rrsets('NSEC')[0]
              if (!nsec || (nsec.length == 0))
                nsec = msg.authority.rrsets('NSEC3')[0]
              end
              if (nsec && (nsec.rrs.length > 0))
                if (!(nsec.rrs()[0].types.include?'DS') || !(nsec.rrs()[0].types.include?'SOA'))
                  next # delegation which we expect to be unsigned - so don't verify it!
                end
              end
            end
            #  If NS records delegate the name to the child's nameservers, then they MUST NOT be signed
            if (rrset.type == Types.NS)
              #               all_delegate = true
              #               rrset.rrs.each {|rr|
              #                 name = Name.create(rr.nsdname)
              #                 name.absolute = true
              #                 if (!(name.subdomain_of?(rr.name)))
              #                   all_delegate = false
              #                 end
              #               }
              #               if (all_delegate && rrset.sigs.length == 0)
              #                 next
              #               end
              if ((rrset.name.canonical == msg.question()[0].qname.canonical) && (rrset.sigs.length == 0))
                next
              end
            end
          end

          if (section == "additional")
            #  check for glue
            #  if the ownername (in the addtional section) of the glue address is the same or longer as the ownername of the NS record, it is glue
            if (msg.additional.size > 0)
              arec = msg.additional.rrsets('A')[0]
              if (!arec || arec.rrs.length == 0)
                arec = msg.additional.rrsets('AAAA')[0]
              end
              ns_rrsets = msg.additional.rrsets('NS')
              ns_rrsets.each {|ns_rrset|
                if (ns_rrset.length > 0)
                  nsname = ns_rrset.rrs()[0].name
                  if (arec && arec.rrs().length > 0)
                    aname = arec.rrs()[0].name
                    if (nsname.subdomain_of?aname)
                      next
                    end
                  end
                end
              }
            end
          end
          #  If records are in additional, and no RRSIG, that's Ok - just don't use them!
          if ((section == "additional") && (rrset.sigs.length == 0))
            #  @TODO@ Make sure that we don't cache these records!
            next
          end
          #  else verify RRSet
          #           print "About to verify #{rrset.name}, #{rrset.type}\n"
          if (!verify_rrset(rrset, keys))
            #             print "FAILED TO VERIFY RRSET #{rrset.name}, #{rrset.type}\n"
            TheLog.debug("Failed to verify rrset")
            return false
          end
        end
      end
      return true
    end

    def verify_nsecs(msg) # :nodoc:
      #  NSEC(3) handling. Get NSEC(3)s in four cases : (RFC 4035, section 3.1.3)
      #  a) No data - <SNAME, SCLASS> matches, but no <SNAME, SCLASS, STYPE) (§3.1.3.1)
      #      - will expect NSEC in Authority (and associated RRSIG)
      #      - NOERROR returned
      #  b) Name error - no RRSets that match <SNAME, SCLASS> either exactly or through wildcard expansion   (§3.1.3.2)
      #      - NSEC wil prove i) no exact match for <SNAME, SCLASS>, and ii) no RRSets that could match through wildcard expansion
      #      - this may be proved in one or more NSECs (and associated RRSIGs)
      #      - NXDOMAIN returned - should ensure we verify!
      #  c) Wildcard answer - No <SNAME, SCLASS> direct matches, but matches <SNAME, SCLASS, STYPE> through wildcard expansion (§3.1.3.3)
      #      - Answer section must include wildcard-expanded answer (and associated RRSIGs)
      #      - label count in answer RRSIG indicates wildcard RRSet was expanded (less labels than in owner name)
      #      - Authority section must include NSEC (and RRSIGs) proving that zone does not contain a closer match
      #      - NOERROR returned
      #  d) Wildcard no data - No <SNAME, SCLASS> direct. <SNAME, SCLASS> yes but <SNAME, SCLASS, STYPE> no through wildcard expansion (§3.1.3.4)
      #      - Authority section contains NSECs (and RRSIGs) for :
      #          i) NSEC proving no RRSets matching STYPE at wildcard owner name that matched <SNAME, SCLASS> via wildcard expansion
      #          ii) NSEC proving no RRSets in zone that would have been closer match for <SNAME, SCLASS>
      #      - this may be proved by one or more NSECs (and associated RRSIGs)
      #      - NOERROR returned
      # 
      #  Otherwise no NSECs should be returned.

      #  So, check for NSEC records in response, and work out what type of answer we have.
      #  Then, if NSECs are present, make sure that we prove what they said they would.
      #  What if the message *should* have no NSEC records? That can only be known by the validator.
      #  We will assume that the validator has checked the (non)-existence of NSEC records - we should not
      #  get upset if there aren't any. However, if there are, then we should verify that they say the right thing
      qtype = msg.question()[0].qtype
      return if (msg.rcode == RCode.NOERROR && ((qtype == Types.ANY) || (qtype == Types.NSEC) || (qtype == Types.NSEC3)))
      if ((msg.rrsets('NSEC').length > 0) || (msg.rrsets('NSEC3').length > 0))
        if (msg.rcode == RCode.NXDOMAIN)
          #           print "Checking NSECs for Name Error\n"
          # Name error - NSEC wil prove i) no exact match for <SNAME, SCLASS>, and ii) no RRSets that could match through wildcard expansion
          #            - this may be proved in one or more NSECs (and associated RRSIGs)
          check_name_in_nsecs(msg)
          return check_no_wildcard_expansion(msg)
        elsif (msg.rcode == RCode.NOERROR)
          if (msg.answer.length > 0)
            #             print "Checking NSECs for wildcard expansion\n"
            #  wildcard expansion answer - check NSECs!
            #  We want to make sure that the NSEC tells us that there is no closer match for this name
            #  @TODO@ We need to make replace the RRSIG name with the wildcard name before we can verify it correctly.
            check_num_rrsig_labels(msg)
            return check_name_in_nsecs(msg, msg.question()[0].qtype, true)
          else
            #  Either no data or wildcard no data - check to see which
            #  Should be able to tell this by checking the number of labels in the NSEC records.
            #  Sort these two last cases out!
            isWildcardNoData = false
            [msg.authority.rrsets('NSEC'), msg.authority.rrsets('NSEC3')].each {|nsec_rrsets|
              nsec_rrsets.each {|nsec_rrset|
                nsec_rrset.rrs.each {|nsec|
                  #                   print "Checking nsec to see if wildcard : #{nsec}\n"
                  if (nsec.name.wild? ||(nsec.name.labels.length < msg.question()[0].qname.labels.length))
                    isWildcardNoData = true
                  end
                }
              }
            }

            if (isWildcardNoData)
              #               print "Checking NSECs for wildcard no data\n"
              #  Check NSECs -
              #          i) NSEC proving no RRSets matching STYPE at wildcard owner name that matched <SNAME, SCLASS> via wildcard expansion
              check_name_not_in_wildcard_nsecs(msg)
              #          ii) NSEC proving no RRSets in zone that would have been closer match for <SNAME, SCLASS>
              return check_name_in_and_type_not_in_nsecs(msg)
            else # (isNoData)
              #               print "Checking NSECs for No data\n"
              #  Check NSEC types covered to make sure this type not present.
              return check_name_in_and_type_not_in_nsecs(msg)
            end
          end
        else
          #  Anything we should do here?
        end
      end

    end

    def check_num_rrsig_labels(msg) # :nodoc:
      #  Check that the number of labels in the RRSIG is less than the number
      #  of labels in the answer name
      answer_rrset = msg.answer.rrset(msg.question()[0].qname, msg.question()[0].qtype)
      if (answer_rrset.length == 0)
        raise VerifyError.new("Expected wildcard expanded answer for #{msg.question()[0].qname}")
      end
      rrsig = answer_rrset.sigs()[0]
      if (rrsig.labels >= msg.question()[0].qname.labels.length)
        raise VerifyError.new("RRSIG does not prove wildcard expansion for #{msg.question()[0].qname}")
      end
    end

    def check_no_wildcard_expansion(msg) # :nodoc:
      #  @TODO@ Do this for NSEC3 records!!!
      proven_no_wildcards = false
      name = msg.question()[0].qname
      [msg.authority.rrsets('NSEC'), msg.authority.rrsets('NSEC3')].each {|nsec_rrsets|
        nsec_rrsets.each {|nsecs|
          nsecs.rrs.each {|nsec|
            #             print "Checking NSEC : #{nsec}\n"
            next if (nsec.name.wild?)
            if (check_record_proves_no_wildcard(msg, nsec))
              proven_no_wildcards = true
            end
          }
        }
      }
      if (!proven_no_wildcards)
        #         print "No proof that no RRSets could match through wildcard expansion\n"
        raise VerifyError.new("No proof that no RRSets could match through wildcard expansion")
      end

    end

    def check_record_proves_no_wildcard(msg, nsec) # :nodoc:
      #  Check that the NSEC goes from the SOA to a zone canonically after a wildcard
      #       print "Checking wildcard proof for #{nsec.name}\n"
      soa_rrset = msg.authority.rrset(nsec.name, 'SOA')
      if (soa_rrset.length > 0)
        #         print "Found SOA for #{nsec.name}\n"
        wildcard_name = Name.create("*." + nsec.name.to_s)
        #         print "Checking #{wildcard_name}\n"
        if (wildcard_name.canonically_before(nsec.next_domain))
          return true
        end
      end
      return false
    end

    def check_name_in_nsecs(msg, qtype=nil, expected_qtype = false) # :nodoc:
      #  Check these NSECs to make sure that this name cannot be in the zone
      #  and that no RRSets could match through wildcard expansion
      #  @TODO@ Get this right for NSEC3 too!
      name = msg.question()[0].qname
      proven_name_in_nsecs = false
      type_covered_checked = false
      [msg.authority.rrsets('NSEC'), msg.authority.rrsets('NSEC3')].each {|nsec_rrsets|
        nsec_rrsets.each {|nsecs|
          nsecs.rrs.each {|nsec|
            #             print "Checking NSEC : #{nsec}\n"
            next if (nsec.name.wild?)
            if nsec.check_name_in_range(name)
              proven_name_in_nsecs = true
              qtype_present = false
              if (qtype)
                if (nsec.types.include?qtype)
                  qtype_present = true
                end
                if (qtype_present != expected_qtype)
                  #                   print "#{nsec.type} record #{nsec} does #{expected_qtype ? 'not ' : ''} include #{qtype} type\n"
                  raise VerifyError.new("#{nsec.type} record #{nsec} does #{expected_qtype ? 'not ' : ''}include #{qtype} type")
                  #               return false
                end
                type_covered_checked = true
              end
            end
          }
        }
      }
      if (!proven_name_in_nsecs)
        #         print "No proof for non-existence for #{name}\n"
        raise VerifyError.new("No proof for non-existence for #{name}")
      end
      if (qtype && !type_covered_checked)
        #         print "Tyes covered wrong for #{name}\n"
        raise VerifyError.new("Types covered wrong for #{name}")
      end
    end

    def check_name_in_and_type_not_in_nsecs(msg) # :nodoc:
      check_name_in_nsecs(msg, msg.question()[0].qtype, false)
    end

    def check_name_not_in_wildcard_nsecs(msg) # :nodoc:
      #  @TODO@ Do this for NSEC3 records too!
      name = msg.question()[0].qname
      qtype = msg.question()[0].qtype
      done= false
      [msg.authority.rrsets('NSEC'), msg.authority.rrsets('NSEC3')].each {|nsec_rrsets|
        nsec_rrsets.each {|nsecs|
          nsecs.rrs.each {|nsec|
            #             print "Checking NSEC : #{nsec}\n"
            next if !nsec.name.wild?
            #  Check the wildcard expansion
            #  We want to see that the name is in the wildcard range, and that the type
            #  is not in the types for the NSEC
            if nsec.check_name_in_wildcard_range(name)
              #               print "Wildcard expansion in #{nsec} includes #{name}\n"
              raise VerifyError.new("Wildcard expansion in #{nsec} includes #{name}")
              #             return false
            end
            if (nsec.types.include?qtype)
              #               print "#{qtype} present in wildcard #{nsec}\n"
              raise VerifyError.new("#{qtype} present in wildcard #{nsec}")
              #             return false
            end
            done = true
          }
        }
      }
      return if done
      #       print("Expected wildcard expansion in #{msg}\n")
      raise VerifyError.new("Expected wildcard expansion in #{msg}")
      #       return false
    end

    def verify_ds_rrset(ds_rrset, keys = nil, msg = nil) # :nodoc:
      #       print "verify_ds_rrset #{ds_rrset}\n"
      if (ds_rrset && ds_rrset.num_sigs > 0)
        if (verify_rrset(ds_rrset, keys))
          #  Need to handle DS RRSets (with RRSIGs) not just DS records.
          #             ds_rrset.rrs.each do |ds|
          #  Work out which key this refers to, and add it to the trusted key store
          found = false
          if (msg)
            msg.each_section do |section|
              section.rrsets('DNSKEY').each {|rrset|
                rrset.rrs.each do |rr|
                  if (check_ds(rr, ds_rrset))
                    found = true
                  end
                end
              }
            end
          end
          get_keys_to_check().each {|key|
            if (check_ds(key, ds_rrset))
              found = true
            end
          }
          #  If we couldn't find the trusted key, then we should store the
          #  key tag and digest in a @@discovered_ds_store.
          #  Each time we see a new key (which has been signed) then we should
          #  check if it is sitting on the discovered_ds_store.
          #  If it is, then we should add it to the trusted_keys and remove the
          #  DS from the discovered_ds_store
          if (!found)
            @discovered_ds_store.push(ds_rrset)
          end
          #             end
          return true
        else
          return false
        end
      end
      return false # no DS rrset to verify
    end

    def verify_key_rrset(key_rrset, keys = nil) # :nodoc:
      #       print "verify_key_rrset\n"
      verified = false
      if (key_rrset && key_rrset.num_sigs > 0)
        if (verify_rrset(key_rrset, keys))
          #             key_rrset.rrs.each do |rr|
          #           print "Adding keys : "
          #           key_rrset.rrs.each {|rr| print "#{rr.key_tag}, "}
          #           print "\n"
          @trusted_keys.add(key_rrset) # rr)
          verified = true
        end
        check_ds_stores(key_rrset)
      end
      return verified
    end

    def check_ds_stores(key_rrset) # :nodoc:
      #  See if the keys match any of the to_be_trusted_keys
      key_rrset.rrs.each do |key|
        @configured_ds_store.each do |ds|
          if (ds.check_key(key))
            @trusted_keys.add_key_with_expiration(key, key_rrset.sigs()[0].expiration)
          end
        end
        @discovered_ds_store.each do |tbtk|
          #  Check that the RRSet is still valid!!
          #  Should we get it out of the main cache?
          if ((tbtk.sigs()[0].expiration < Time.now.to_i))
            @discovered_ds_store.delete(tbtk)
          else
            tbtk.rrs.each {|ds|
              if (ds.check_key(key))
                @trusted_keys.add_key_with_expiration(key, tbtk.sigs()[0].expiration)
                @discovered_ds_store.delete(tbtk)
              end
            }
          end
        end
        #             end
      end

    end

    def get_keys_to_check # :nodoc:
      keys_to_check = @trust_anchors.keys + @trusted_keys.keys
      return keys_to_check
    end

    #  Find the first matching DNSKEY and RRSIG record in the two sets.
    def get_matching_key(keys, sigrecs)#:nodoc: all
      #  There can be multiple signatures in the RRSet - which one should we choose?
      if ((keys == nil) || (sigrecs == nil))
        return nil, nil
      end
      if ((RR::DNSKEY === keys) || (RR::DS === keys) ||
            ((RR::DLV === keys) && (@verifier_type == VerifierType::DLV)))
        keys = [keys]
      end
      enumerator = keys
      if (enumerator.class == RRSet)
        enumerator = enumerator.rrs
      end
      enumerator.each {|key|
        if ((key.revoked?)) # || (key.bad_flags?))
          next
        end

        sigrecs.each {|sig|
#          print "Looking at #{sig.key_tag} on sig, #{key.key_tag} on key\n"
          if ((key.key_tag == sig.key_tag) && (key.algorithm == sig.algorithm))
#                                    print "Found key #{key.key_tag}\n"
            return key, sig
          end
        }
      }
      return nil, nil
    end

    #  Verify the signature of an rrset encoded with the specified KeyCache
    #  or RRSet. If no signature is included, false is returned.
    # 
    #  Returns true if the RRSet verified, false otherwise.
    def verify_rrset(rrset, keys = nil)
      #       print "Verify_rrset #{rrset.name}, #{rrset.type}\n"
#      print "ABOUT TO VERIFY WITH #{keys == nil ? '0' : keys.length} keys\n"
#      if (keys != nil)
#        if (keys.length > 0)
#          print "KEY TAG : #{keys[0].key_tag}\n"
#        end
#      end
      sigrecs = rrset.sigs
      if (rrset.rrs.length == 0)
        raise VerifyError.new("No RRSet to verify")
      end
      if (rrset.num_sigs == 0)
        raise VerifyError.new("No signatures in the RRSet : #{rrset.name}, #{rrset.type}")
      end
      sigrecs.each do |sigrec|
        check_rr_data(rrset, sigrec)
      end
      raise ArgumentError.new("Expecting DNSKEY, DLV, DS, RRSet, Array or nil for keys : got #{keys.class} instead") if
      (keys && (![Array, RR::IN::DNSKEY, RR::IN::DLV, RR::IN::DS].include?keys.class) && (keys.class != RRSet))

      keyrec = nil
      sigrec = nil
      if (rrset.type == Types.DNSKEY)
        if (keys && !(Array === keys) && ((keys.type == Types.DS) || ((keys.type == Types.DLV) && (@verifier_type == VerifierType::DLV))))
          rrset.rrs.each do |key|
            keys.rrs.each do |ds|
              if (ds.check_key(key))
                @trusted_keys.add_key_with_expiration(key, rrset.sigs()[0].expiration)
              end
            end
          end
        else
          check_ds_stores(rrset)
        end
      end
      if ((keys.nil?) || ((keys.class != Array) && ((keys.type == Types.DS) || ((keys.type == Types.DLV) && (@verifier_type == VerifierType::DLV)))))
        keyrec, sigrec = get_matching_key(get_keys_to_check, sigrecs)
      else
        keyrec, sigrec = get_matching_key(keys, sigrecs)
      end

      #       return false if !keyrec
      if (!keyrec)
        #         print "Couldn't find signing key! #{rrset.name}, #{rrset.type},\n "
        raise VerifyError.new("Signing key not found")
      end

      #  RFC 4034
      # 3.1.8.1.  Signature Calculation

      if (keyrec.sep_key? && !keyrec.zone_key?)
        Dnsruby.log.error("DNSKEY with SEP flag set and Zone Key flag not set was used to verify RRSIG over RRSET - this is not allowed by RFC4034 section 2.1.1")
        #         return false
        raise VerifyError.new("DNSKEY with SEP flag set and Zone Key flag not set")
      end


#      print "VERIFY KEY FOUND - doing verification\n"

      # Any DNS names in the RDATA field of each RR MUST be in
      # canonical form; and
      # The RRset MUST be sorted in canonical order.
      rrset = rrset.sort_canonical

      sig_data = sigrec.sig_data

      # RR(i) = owner | type | class | TTL | RDATA length | RDATA
      rrset.each do |rec|
        old_ttl = rec.ttl
        rec.ttl = sigrec.original_ttl
        data = MessageEncoder.new { |msg|
          msg.put_rr(rec, true)
        }.to_s # @TODO@ worry about wildcards here?
        rec.ttl = old_ttl
        if (RUBY_VERSION >= "1.9")
          data.force_encoding("ASCII-8BIT")
        end
        sig_data += data
      end

      #  Now calculate the signature
      verified = false
      if [Algorithms.RSASHA1,
          Algorithms.RSASHA1_NSEC3_SHA1].include?(sigrec.algorithm)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA1.new, sigrec.signature, sig_data)
      elsif (sigrec.algorithm == Algorithms.RSASHA256)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA256.new, sigrec.signature, sig_data)
      elsif (sigrec.algorithm == Algorithms.RSASHA512)
        verified = keyrec.public_key.verify(OpenSSL::Digest::SHA512.new, sigrec.signature, sig_data)
      elsif [Algorithms.DSA,
          Algorithms.DSA_NSEC3_SHA1].include?(sigrec.algorithm)
        #  we are ignoring T for now
        #  t = sigrec.signature[0]
        #  t = t.getbyte(0) if t.class == String
        r = RR::get_num(sigrec.signature[1, 20])
        s = RR::get_num(sigrec.signature[21, 20])
        r_asn1 = OpenSSL::ASN1::Integer.new(r)
        s_asn1 = OpenSSL::ASN1::Integer.new(s)

        asn1 = OpenSSL::ASN1::Sequence.new([r_asn1, s_asn1]).to_der
        verified = keyrec.public_key.verify(OpenSSL::Digest::DSS1.new, asn1, sig_data)
      else
        raise RuntimeError.new("Algorithm #{sigrec.algorithm.code} unsupported by Dnsruby")
      end

      if (!verified)
        raise VerifyError.new("Signature failed to cryptographically verify")
      end
      #  Sort out the TTLs - set it to the minimum valid ttl
      expiration_diff = (sigrec.expiration.to_i - Time.now.to_i).abs
      rrset.ttl = ([rrset.ttl, sigrec.ttl, sigrec.original_ttl,
          expiration_diff].sort)[0]
      #             print "VERIFIED OK\n"
      return true
    end

    def find_closest_dlv_anchor_for(name) # :nodoc:
      #  To find the closest anchor, query DLV.isc.org for [a.b.c.d], then [a.b.c], [a.b], etc.
      #  once closest anchor found, simply run follow_chain from that anchor

      #  @TODO@ REALLY NEED AGGRESSIVE NEGATIVE CACHING HERE!!
      #  i.e. don't look up zones which we *know* we don't have a DLV anchor for

      n = Name.create(name)
      root = Name.create(".")
      while (n != root)
        #  Try to find name in DLV, and return it if possible
        dlv_rrset = query_dlv_for(n)
        if (dlv_rrset)
          key_rrset = get_zone_key_from_dlv_rrset(dlv_rrset, n)
          return key_rrset
        end
        #  strip the name
        n = n.strip_label
      end
      return false
    end

    def get_zone_key_from_dlv_rrset(dlv_rrset, name) # :nodoc:
      #  We want to return the key for the zone i.e. DS/DNSKEY for .se, NOT DLV for se.dlv.isc.org
      #  So, we have the DLv record. Now use it to add the zone's DNSKEYs to the trusted key set.
      res = get_nameservers_for(name)
      if (!res)
        if (Dnssec.do_validation_with_recursor?)
          res = get_recursor
        else
          if(Dnssec.default_resolver)
            res = Dnssec.default_resolver
          else
            res = Resolver.new
          end
        end
      end
      res.dnssec = true
      #       query = Message.new(name, Types.DNSKEY)
      #       query.do_validation = false
      ret = nil
      begin
        #         ret = res.send_message(query)
        ret = res.query_no_validation_or_recursion(name, Types.DNSKEY)
        if (!ret)
          raise ResolvError.new("Couldn't get DNSKEY from Recursor")
        end
      rescue ResolvError => e
        #         print "Error getting zone key from DLV RR for #{name} : #{e}\n"
        TheLog.error("Error getting zone key from DLV RR for #{name} : #{e}")
        return false
      end
      key_rrset = ret.answer.rrset(name, Types.DNSKEY)
      begin
        verify(key_rrset, dlv_rrset)
        #         Cache.add(ret)
        return key_rrset
      rescue VerifyError => e
        #         print "Can't move from DLV RR to zone DNSKEY for #{name}, error : #{e}\n"
        TheLog.debug("Can't move from DLV RR to zone DNSKEY for #{name}, error : #{e}")
      end
      return false
    end

    def query_dlv_for(name) # :nodoc:
      #  See if there is a record for name in dlv.isc.org
      if (!@res && (@verifier_type == VerifierType::DLV))
        @res = get_dlv_resolver
      end
      begin
        name_to_query = name.to_s+".dlv.isc.org"
        #         query = Message.new(name_to_query, Types.DLV)
        #         @res.single_resolvers()[0].prepare_for_dnssec(query)
        #         query.do_validation = false
        ret = nil
        begin
          #           ret = @res.send_message(query)
          ret = @res.query_no_validation_or_recursion(name_to_query, Types.DLV)
          if (!ret)
            raise ResolvError.new("Couldn't get DLV record from Recursor")
          end
        rescue ResolvError => e
          #           print "Error getting DLV record for #{name} : #{e}\n"
          TheLog.info("Error getting DLV record for #{name} : #{e}")
          return nil
        end
        dlv_rrset = ret.answer.rrset(name_to_query,Types.DLV)
        if (dlv_rrset.rrs.length > 0)
          begin
            verify(dlv_rrset)
            #             Cache.add(ret)
            return dlv_rrset
          rescue VerifyError => e
            #             print "Error verifying DLV records for #{name}, #{e}\n"
            TheLog.info("Error verifying DLV records for #{name}, #{e}")
          end
        end
      rescue NXDomain
        #         print "NXDomain for DLV lookup for #{name}\n"
        return nil
      end
      return nil
    end

    def find_closest_anchor_for(name) # :nodoc:
      #  Check if we have an anchor for name.
      #  If not, strip off first label and try again
      #  If we get to root, then return false
      name = "." if name == ""
      n = Name.create(name)
      root = Name.create(".")
      while (true) # n != root)
        #  Try the trusted keys first, then the DS set
        (@trust_anchors.keys + @trusted_keys.keys + @configured_ds_store + @discovered_ds_store).each {|key|
          return key if key.name.canonical == n.canonical
        }
        break if (n.to_s == root.to_s)
        #  strip the name
        n = n.strip_label
      end
      return false
    end

    #  @TODO@ Handle REVOKED keys! (RFC 5011)
    #  Remember that revoked keys will have a different key_tag than pre-revoked.
    #  So, if we see a revoked key, we should go through our key store for
    #  that authority and remove any keys with the pre-revoked key_tag.

    def follow_chain(anchor, name) # :nodoc:
      #  Follow the chain from the anchor to name, returning the appropriate
      #  key at the end, or false.
      # 
      #  i.e. anchor = se, name = foo.example.se
      #    get anchor for example.se with se anchor
      #    get anchor for foo.example.se with example.se anchor
      next_key = anchor
      next_step = anchor.name
      parent = next_step
      #       print "Follow chain from #{anchor.name} to #{name}\n"
      TheLog.debug("Follow chain from #{anchor.name} to #{name}")

      #       res = nil
      res = Dnssec.default_resolver
      #       while ((next_step != name) || (next_key.type != Types.DNSKEY))
      while (true)
        #         print "In loop for parent=#{parent}, next step = #{next_step}\n"
        dont_move_on = false
        if (next_key.type != Types.DNSKEY)
          dont_move_on = true
        end
        next_key, res = get_anchor_for(next_step, parent, next_key, res)
        if (next_step.canonical.to_s == name.canonical.to_s)
          #       print "Returning #{next_key.type} for #{next_step}, #{(next_key.type != Types.DNSKEY)}\n"
          return next_key
        end
        return false if (!next_key)
        #  Add the next label on
        if (!dont_move_on)
          parent = next_step
          next_step = Name.new(name.labels[name.labels.length-1-next_step.labels.length,1] +
              next_step.labels , name.absolute?)
          #           print "Next parent = #{parent}, next_step = #{next_step}, next_key.type = #{next_key.type.string}\n"
        end
      end

      #       print "Returning #{next_key.type} for #{next_step}, #{(next_key.type != Types.DNSKEY)}\n"

      return next_key
    end

    def get_anchor_for(child, parent, current_anchor, parent_res = nil) # :nodoc:
      #       print "Trying to discover anchor for #{child} from #{parent}\n"
      TheLog.debug("Trying to discover anchor for #{child} from #{parent} using #{current_anchor}, #{parent_res}")
      #  We wish to return a DNSKEY which the caller can use to verify name
      #  We are either given a key or a ds record from the parent zone
      #  If given a DNSKEY, then find a DS record signed by that key for the child zone
      #  Use the DS record to find a valid key in the child zone
      #  Return it

      #  Find NS RRSet for parent
      child_res = nil
      if (Dnssec.do_validation_with_recursor?)
        parent_res = get_recursor
        child_res = get_recursor
      end
      begin
        if (child!=parent)
          if (!parent_res)
            #                       print "No res passed - try to get nameservers for #{parent}\n"
            parent_res = get_nameservers_for(parent)
            if (!parent_res)
              if (Dnssec.do_validation_with_recursor?)
                parent_res = get_recursor
              else
                if (Dnssec.default_resolver)
                  parent_res = Dnssec.default_resolver
                else
                  parent_res = Resolver.new
                end
              end
            end
            parent_res.dnssec = true
          end
          #  Use that Resolver to query for DS record and NS for children
          ds_rrset = current_anchor
          if (current_anchor.type == Types.DNSKEY)
            #             print "Trying to find DS records for #{child} from servers for #{parent}\n"
            TheLog.debug("Trying to find DS records for #{child} from servers for #{parent}")
            ds_ret = nil
            begin
              ds_ret = parent_res.query_no_validation_or_recursion(child, Types.DS)
              if (!ds_ret)
                raise ResolvError.new("Couldn't get DS records from Recursor")
              end
            rescue ResolvError => e
              #               print "Error getting DS record for #{child} : #{e}\n"
              TheLog.error("Error getting DS record for #{child} : #{e}")
              return false, nil
            end
            ds_rrset = ds_ret.answer.rrset(child, Types.DS)
            if (ds_rrset.rrs.length == 0)
              #  @TODO@ Check NSEC(3) records - still need to verify there are REALLY no ds records!
              #               print "NO DS RECORDS RETURNED FOR #{parent}\n"
              #               child_res = parent_res
            else
              begin
                if (verify(ds_rrset, current_anchor) || verify(ds_rrset))
                  #  Try to make the resolver from the authority/additional NS RRSets in DS response
                  if (!Dnssec.do_validation_with_recursor?)
                    child_res = get_nameservers_from_message(child, ds_ret)
                  end
                end
              rescue VerifyError => e
                #                 print "FAILED TO VERIFY DS RRSET FOR #{child}\n"
                TheLog.info("FAILED TO VERIFY DS RRSET FOR #{child}")
                # return false, nil
                # raise ResolvError.new("FAILED TO VERIFY DS RRSET FOR #{child}")
                raise VerifyError.new("FAILED TO VERIFY DS RRSET FOR #{child}")
              end
            end
          end
        end
        #  Make Resolver using all child NSs
        if (!child_res)
          child_res = get_nameservers_for(child, parent_res)
        end
        if (!child_res)
          if (Dnssec.do_validation_with_recursor?)
            child_res = get_recursor
          else
            if (Dnssec.default_resolver)
              child_res = Dnssec.default_resolver
            else
              if (Dnssec.default_resolver)
                child_res = Dnssec.default_resolver
              else
                child_res = Resolver.new
              end
            end
            child_res.dnssec = true
          end
        end
        #  Query for DNSKEY record, and verify against DS in parent.
        #  Need to get resolver NOT to verify this message - we verify it afterwards
        #         print "Trying to find DNSKEY records for #{child} from servers for #{child}\n"
        TheLog.info("Trying to find DNSKEY records for #{child} from servers for #{child}")
        #         query = Message.new(child, Types.DNSKEY)
        #         query.do_validation = false
        key_ret = nil
        begin
          #           key_ret = child_res.send_message(query)
          key_ret = child_res.query_no_validation_or_recursion(child, Types.DNSKEY)
          if (!key_ret)
            raise ResolvError.new("Couldn't get info from Recursor")
          end
        rescue ResolvError => e
          #           print "Error getting DNSKEY for #{child} : #{e}\n"
          TheLog.error("Error getting DNSKEY for #{child} : #{e}")
          # return false, nil
          raise VerifyError.new("Error getting DNSKEY for #{child} : #{e}")
        end
        verified = true
        key_rrset = key_ret.answer.rrset(child, Types.DNSKEY)
        if (key_rrset.rrs.length == 0)
          #  @TODO@ Still need to check NSEC records to make *sure* no key rrs returned!
          #           print "NO DNSKEY RECORDS RETURNED FOR #{child}\n"
          TheLog.debug("NO DNSKEY RECORDS RETURNED FOR #{child}")
          #         end
          verified = false
        else
          #  Should check that the matching key's zone flag is set (RFC 4035 section 5.2)
          key_rrset.rrs.each {|k|
            if (!k.zone_key?)
              #               print "Discovered DNSKEY is not a zone key - ignoring\n"
              TheLog.debug("Discovered DNSKEY is not a zone key - ignoring")
              return false, child_res
            end
          }
          begin
            verify(key_rrset, ds_rrset)
          rescue VerifyError => e
            begin
              verify(key_rrset)
            rescue VerifyError =>e
              verified = false
              raise VerifyError.new("Couldn't verify DNSKEY and DS records")
            end
          end
        end

        #  Try to make the resolver from the authority/additional NS RRSets in DNSKEY response
        new_res = get_nameservers_from_message(child,  key_ret) # @TODO@ ?
        if (!new_res)
          new_res = child_res
        end
        if (!verified)
          TheLog.info("Failed to verify DNSKEY for #{child}")
          return false, nil # new_res
          # raise VerifyError.new("Failed to verify DNSKEY for #{child}")
        end
        #         Cache.add(key_ret)
        return key_rrset, new_res
      rescue VerifyError => e
        #         print "Verification error : #{e}\n"
        TheLog.info("Verification error : #{e}\n")
        # return false, nil # new_res
        raise VerifyError.new("Verification error : #{e}\n")
      end
    end

    def get_nameservers_for(name, res = nil) # :nodoc:
      #  @TODO@ !!!
      if (Dnssec.do_validation_with_recursor?)
        return get_recursor
      else
        resolver = nil
        if (Dnssec.default_resolver)
          resolver = Dnssec.default_resolver
        else
          resolver = Resolver.new
        end
        resolver.dnssec = true
        return resolver
      end
    end

    def get_nameservers_from_message(name, ns_ret) # :nodoc:
      if (Dnssec.default_resolver)
        return Dnssec.default_resolver
      end

      ns_rrset = ns_ret.answer.rrset(name, Types.NS)
      if (!ns_rrset || ns_rrset.length == 0)
        ns_rrset = ns_ret.authority.rrset(name, Types.NS) # @TODO@ Is ths OK?
      end
      if (!ns_rrset || ns_rrset.length == 0 || ns_rrset.name.canonical != name.canonical)
        return nil
      end
      if (ns_rrset.sigs.length > 0)
        #                 verify_rrset(ns_rrset) # @TODO@ ??
      end
      #       Cache.add(ns_ret)
      ns_additional = []
      ns_ret.additional.each {|rr| ns_additional.push(rr) if (rr.type == Types.A) }
      nameservers = []
      add_nameservers(ns_rrset, ns_additional, nameservers) # if (ns_additional.length > 0)
      ns_additional = []
      ns_ret.additional.each {|rr| ns_additional.push(rr) if (rr.type == Types.AAAA) }
      add_nameservers(ns_rrset, ns_additional, nameservers) if (ns_additional.length > 0)
      #  Make Resolver using all NSs
      if (nameservers.length == 0)
        #         print "Can't find nameservers for #{ns_ret.question()[0].qname} from #{ns_rrset.rrs}\n"
        TheLog.info("Can't find nameservers for #{ns_ret.question()[0].qname} from #{ns_rrset.rrs}")
        return  nil # @TODO@ Could return a recursor here?
        # return Recursor.new
      end
      res = Resolver.new()
      res.nameserver=(nameservers)
      #  Set the retry_delay to be (at least) the number of nameservers
      #  Otherwise, the queries will be sent at a rate of more than one a second!
      res.retry_delay = nameservers.length * 2
      res.dnssec = true
      return res
    end

    def add_nameservers(ns_rrset, ns_additional, nameservers) # :nodoc:
      #  Want to go through all of the ns_rrset NS records,
      #       print "Checking #{ns_rrset.rrs.length} NS records against #{ns_additional.length} address records\n"
      ns_rrset.rrs.sort_by {rand}.each {|ns_rr|
        #    and see if we can find any of the names in the A/AAAA records in ns_additional
        found_addr = false
        ns_additional.each {|addr_rr|
          if (ns_rr.nsdname.canonical == addr_rr.name.canonical)
            #             print "Found address #{addr_rr.address} for #{ns_rr.nsdname}\n"
            nameservers.push(addr_rr.address.to_s)
            found_addr = true
            break
            #  If we can, then we add the server A/AAAA address to nameservers
          end
          #  If we can't, then we add the server NS name to nameservers

        }
        if (!found_addr)
          #           print "Couldn't find address - adding #{ns_rr.nsdname}\n"
          nameservers.push(ns_rr.nsdname)
        end

      }
    end

    def validate_no_rrsigs(msg) # :nodoc:
      #       print "Validating unsigned response\n"
      #  WHAT IF THERE ARE NO RRSIGS IN MSG?
      #  Then we need to check that we do not expect any RRSIGs
      if (!msg.question()[0] && msg.answer.length == 0)
        #         print "Returning Message insecure OK\n"
        msg.security_level = Message::SecurityLevel.INSECURE
        return true
      end
      qname = msg.question()[0].qname
      closest_anchor = find_closest_anchor_for(qname)
      #       print "Found closest anchor :#{closest_anchor}\n"
      if (closest_anchor)
        actual_anchor = follow_chain(closest_anchor, qname)
        #         print "Actual anchor : #{actual_anchor}\n"
        if (actual_anchor)
          #           print("Anchor exists for #{qname}, but no signatures in #{msg}\n")
          TheLog.error("Anchor exists for #{qname}, but no signatures in #{msg}")
          msg.security_level = Message::SecurityLevel.BOGUS
          return false
        end
      end
      if ((@verifier_type == VerifierType::DLV) &&
            @added_dlv_key)
        #  Remember to check DLV registry as well (if appropriate!)
        #         print "Checking DLV for closest anchor\n"
        dlv_anchor = find_closest_dlv_anchor_for(qname)
        #         print "Found DLV closest anchor :#{dlv_anchor}\n"
        if (dlv_anchor)
          actual_anchor = follow_chain(dlv_anchor, qname)
          #           print "Actual anchor : #{actual_anchor}\n"
          if (actual_anchor)
            #             print("DLV Anchor exists for #{qname}, but no signatures in #{msg}\n")
            TheLog.error("DLV Anchor exists for #{qname}, but no signatures in #{msg}")
            msg.security_level = Message::SecurityLevel.BOGUS
            return false
          end

        end
      end
      #       print "Returning Message insecure OK\n"
      msg.security_level = Message::SecurityLevel.INSECURE
      return true
    end

    def validate(msg, query)
      if (msg.rrsets('RRSIG').length == 0)
        return validate_no_rrsigs(msg)
      end

      #  See if it is a child of any of our trust anchors.
      #  If it is, then see if we have a trusted key for it
      #  If we don't, then see if we can get to it from the closest
      #  trust anchor
      #  Otherwise, try DLV (if configured)
      # 
      # 
      #  So - find closest existing trust anchor
      error = nil
      msg.security_level = Message::SecurityLevel.INDETERMINATE
      qname = msg.question()[0].qname
      closest_anchor = find_closest_anchor_for(qname)
      if (!closest_anchor)

      end
      TheLog.debug("Closest anchor for #{qname} is #{closest_anchor} - trying to follow down")
      error = try_to_follow_from_anchor(closest_anchor, msg, qname)

      if ((msg.security_level.code < Message::SecurityLevel::SECURE) &&
            (@verifier_type == VerifierType::DLV) &&
            @added_dlv_key)
        #  If we can't find anything, and we're set to check DLV, then
        #  check the DLV registry and work down from there.
        dlv_anchor = find_closest_dlv_anchor_for(qname)
        if (dlv_anchor)
          #           print "Trying to follow DLV anchor from #{dlv_anchor.name} to #{qname}\n"
          TheLog.debug("Trying to follow DLV anchor from #{dlv_anchor.name} to #{qname}")
          error = try_to_follow_from_anchor(dlv_anchor, msg, qname)
        else
          #           print "Couldn't find DLV anchor for #{qname}\n"
          TheLog.debug("Couldn't find DLV anchor for #{qname}")
        end
      end
      if (msg.security_level.code != Message::SecurityLevel::SECURE)
        begin
          #           print "Trying to verify one last time\n"

          if verify(msg) # Just make sure we haven't picked the keys up anywhere
            msg.security_level = Message::SecurityLevel.SECURE
            return true
          end
        rescue VerifyError => e
          #           print "Verify failed : #{e}\n"
        end
      end
      if (error)
        raise error
      end
      if (msg.security_level == Message::SecurityLevel.BOGUS)
        raise VerifyError.new("Bogus record")
      end
      if (msg.security_level.code > Message::SecurityLevel::UNCHECKED)
        return true
      else
        return false
      end
    end

    def try_to_follow_from_anchor(closest_anchor, msg, qname) # :nodoc:
      error = nil
      if (closest_anchor)
        #  Then try to descend to the level we're interested in
        actual_anchor = false
        begin
          actual_anchor = follow_chain(closest_anchor, qname)
        rescue VerifyError => e
          TheLog.debug("Broken chain from anchor : #{closest_anchor.name}")
          msg.security_level = Message::SecurityLevel.BOGUS
          return e
        end
        # @TODO@ We need to de ermine whether there was simply no DS record, or whether there was a failure
        if (!actual_anchor)
          TheLog.debug("Unable to follow chain from anchor : #{closest_anchor.name}")
          msg.security_level = Message::SecurityLevel.INSECURE
        else
          actual_anchor_keys = ""
          actual_anchor.rrs.each {|rr| actual_anchor_keys += ", #{rr.key_tag}"}
          TheLog.debug("Found anchor #{actual_anchor.name}, #{actual_anchor.type} for #{qname} : #{actual_anchor_keys}")
          #           print "Found anchor #{actual_anchor.name}, #{actual_anchor.type} for #{qname} : #{actual_anchor_keys}\n"
          begin
            if (verify(msg, actual_anchor))
              TheLog.debug("Validated #{qname}")
              msg.security_level = Message::SecurityLevel.SECURE
            end
          rescue VerifyError => e
            TheLog.info("BOGUS #{qname}! Error : #{e}")
            #             print "BOGUS #{qname}! Error : #{e}\n"
            msg.security_level = Message::SecurityLevel.BOGUS
            error = e
          end
        end
      else
        #         print "Unable to find an anchor for #{qname}\n"
        msg.security_level = Message::SecurityLevel.INSECURE
      end
      return error
    end

  end
end