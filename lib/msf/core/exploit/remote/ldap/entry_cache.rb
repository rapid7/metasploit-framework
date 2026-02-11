require 'lru_redux'

module Msf
  ###
  #
  # This module exposes methods for querying a remote LDAP service
  #
  ###
  module Exploit::Remote::LDAP
    module EntryCache
      class LDAPEntryCache < LruRedux::Cache
        MissingEntry = Object.new.freeze

        def initialize(max_size: 1000)
          super(max_size)
          @missing_samaccountname = LruRedux::Cache.new(max_size)
          @missing_sid = LruRedux::Cache.new(max_size)
        end

        def <<(entry)
          raise TypeError unless entry.is_a? Net::LDAP::Entry

          self[entry.dn] = entry
        end

        def get_by_dn(dn)
          self[dn]
        end

        def get_by_samaccountname(samaccountname)
          entry = @data.values.reverse_each.find { _1.is_a?(Net::LDAP::Entry) && _1[:sAMAccountName]&.first == samaccountname }
          @data[entry.dn] = entry if entry # update it as recently used
          return entry if entry

          MissingEntry if @missing_samaccountname[samaccountname]
        end

        def get_by_sid(sid)
          sid = Rex::Proto::MsDtyp::MsDtypSid.new(sid)

          entry = @data.values.reverse_each.find { _1.is_a?(Net::LDAP::Entry) && _1[:objectSid]&.first == sid.to_binary_s  }
          @data[entry.dn] = entry if entry # update it as recently used
          return entry if entry

          MissingEntry if @missing_sid[sid.to_s]
        end

        def mark_missing_by_dn(dn)
          self[dn] = MissingEntry
        end

        def mark_missing_by_samaccountname(samaccountname)
          @missing_samaccountname[samaccountname] = true
        end

        def mark_missing_by_sid(sid)
          sid = Rex::Proto::MsDtyp::MsDtypSid.new(sid)
          @missing_sid[sid.to_s] = true
        end

        def missing_entry?(entry)
          entry.equal?(MissingEntry)
        end
      end

      def ldap_entry_cache
        @ldap_entry_cache ||= LDAPEntryCache.new(max_size: 1000)
      end
    end
  end
end
