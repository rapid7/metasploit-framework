# -*- coding: binary -*-

require 'rex/socket'

module Rex
module Proto
module DNS
  class Cache
    attr_reader :records, :lock, :monitor_thread
    include Rex::Proto::DNS::Constants
    # class DNSRecordError < ::Exception
    #
    # Create DNS cache
    #
    def initialize
      @records = {}
      @lock = Mutex.new
    end

    #
    # Find entries in cache, substituting names for '*' in return
    #
    # @param search [String] Name or address to search for
    # @param type [Dnsruby::Types] Record type to search for
    #
    # @return [Array] Records found
    def find(search, type = Dnsruby::Types::A)
      self.records.select do |record,expire|
        record.type == type and (expire < 1 or expire > ::Time.now.to_i) and
        (
          record.name == '*' or
          record.name.to_s == search.to_s or record.name.to_s[0..-2] == search.to_s or
          ( record.respond_to?(:address) and record.address.to_s == search.to_s )
        )
      end.keys.map do |record|
        if search.to_s.match(MATCH_HOSTNAME) and record.name == '*'
          record = Dnsruby::RR.create(name: name, type: type, address: address)
        else
          record
        end
      end
    end

    #
    # Add record to cache, only when "running"
    #
    # @param record [Dnsruby::RR] Record to cache
    def cache_record(record)
      return unless @monitor_thread
      if record.is_a?(Dnsruby::RR) and
      (!record.respond_to?(:address) or Rex::Socket.is_ip_addr?(record.address.to_s)) and
      record.name.to_s.match(MATCH_HOSTNAME)
        add(record, ::Time.now.to_i + record.ttl)
      else
        raise "Invalid record for cache entry - #{record.inspect}"
      end
    end

    #
    # Add static record to cache
    #
    # @param name [String] Name of record
    # @param address [String] Address of record
    # @param type [Dnsruby::Types] Record type to add
    # @param replace [TrueClass, FalseClass] Replace existing records
    def add_static(name, address, type = Dnsruby::Types::A, replace = false)
      if Rex::Socket.is_ip_addr?(address.to_s) and
      ( name.to_s.match(MATCH_HOSTNAME) or name == '*')
        find(name, type).each do |found|
          delete(found)
        end if replace
        add(Dnsruby::RR.create(name: name, type: type, address: address),0)
      else
        raise "Invalid parameters for static entry - #{name}, #{address}, #{type}"
      end
    end

    #
    # Prune cache entries
    #
    # @param before [Fixnum] Time in seconds before which records are evicted
    def prune(before = ::Time.now.to_i)
      self.records.select do |rec, expire|
        expire > 0 and expire < before
      end.each {|rec, exp| delete(rec)}
    end

    #
    # Start the cache monitor
    #
    def start
      @monitor_thread = Rex::ThreadFactory.spawn("DNSServerCacheMonitor", false) {
        while true
          prune
          Rex::ThreadSafe.sleep(0.5)
        end
      } unless @monitor_thread
    end

    #
    # Stop the cache monitor
    #
    # @param flush [TrueClass,FalseClass] Remove non-static entries
    def stop(flush = false)
      self.monitor_thread.kill unless @monitor_thread.nil?
      @monitor_thread = nil
      if flush
        self.records.select do |rec, expire|
          rec.ttl > 0
        end.each {|rec| delete(rec)}
      end
    end

    protected

    #
    # Add a record to the cache with thread safety
    #
    # @param record [Dnsruby::RR] Record to add
    # @param expire [Fixnum] Time in seconds when record becomes stale
    def add(record, expire = 0)
      self.lock.synchronize do
        self.records[record] = expire
      end
    end

    #
    # Delete a record from the cache with thread safety
    #
    # @param record [Dnsruby::RR] Record to delete
    def delete(record)
      self.lock.synchronize do
        self.records.delete(record)
      end
    end
  end # Cache
end
end
end
