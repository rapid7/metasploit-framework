require 'monitor'

module Msf
  module RPC
    class RpcJobStatusTracker

      include MonitorMixin

      def initialize
        @ready = Set.new
        @running = Set.new
        # Can be expanded upon later to allow the option of a MemCacheStore being backed by redis for example
        @results = ResultsMemoryStore.new
      end

      def waiting(id)
        ready << id
      end

      def start(id)
        running << id
        ready.delete(id)
      end

      def completed(id, result, mod)
        add_result(id, { result: result }, mod)
      end

      def failed(id, error, mod)
        add_result(id, { error: error.to_s }, mod)
      end

      def running?(id)
        running.include? id
      end

      def waiting?(id)
        ready.include? id
      end

      def finished?(id)
        results.exist? id
      end

      def result(id)
        result = results.fetch(id)
        return unless result

        ::JSON.parse(result).with_indifferent_access
      end

      def delete(id)
        results.delete(id)
      end

      def result_ids
        results.keys
      end

      def waiting_ids
        ready.to_a
      end

      def running_ids
        running.to_a
      end

      def data
        results.data
      end

      alias ack delete

      private

      def add_result(id, result, mod)
        string = result.to_json
        results.write(id, string)
      rescue ::Exception => e
        wlog("Job with id: #{id} finished but the result could not be stored")
        wlog("#{e.class}, #{e.message}")
        add_fallback_result(id, mod)
      ensure
        running.delete(id)
      end

      def add_fallback_result(id, mod)
        string = {
          error: {
            message: 'Job finished but the result could not be stored',
            data: { mod: mod.fullname }
          }
        }.to_json
        results.write(id, string)
      rescue ::Exception => e
        wlog("Job with id: #{id} fallback result failed to be stored")
        wlog("#{e.class}, #{e.message}")
      end

      attr_accessor :ready, :running, :results

      class ResultsMemoryStore < ActiveSupport::Cache::MemoryStore
        def keys
          @data.keys
        end
      end
    end
  end
end
