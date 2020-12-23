require 'monitor'

module Msf
  module RPC
    class RpcJobStatusTracker

      include MonitorMixin

      def initialize
        super
        @ready = Set.new
        @running = Set.new
        # Can be expanded upon later to allow the option of a MemCacheStore being backed by redis for example
        @results = ResultsMemoryStore.new
      end

      def waiting(id)
        synchronize do
          ready << id
        end
      end

      def start(id)
        synchronize do
          running << id
          ready.delete(id)
        end
      end

      def completed(id, result, mod)
        synchronize do
          add_result(id, { result: result }, mod)
        end
      end

      def failed(id, error, mod)
        synchronize do
          add_result(id, { error: error.to_s }, mod)
        end
      end

      def running?(id)
        synchronize do
          running.include? id
        end
      end

      def waiting?(id)
        synchronize do
          ready.include? id
        end
      end

      def finished?(id)
        synchronize do
          results.exist? id
        end
      end

      def result(id)
        synchronize do
          result = results.fetch(id)
          return unless result

          ::JSON.parse(result).with_indifferent_access
        end
      end

      def delete(id)
        synchronize do
          results.delete(id)
        end
      end

      def result_ids
        synchronize do
          results.keys
        end
      end

      def waiting_ids
        synchronize do
          ready.to_a
        end
      end

      def running_ids
        synchronize do
          running.to_a
        end
      end

      def data
        synchronize do
          results.data
        end
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
