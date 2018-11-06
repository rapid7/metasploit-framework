# frozen_string_literal: true

require "json"

#
# Singleton that is responsible for caching, loading and merging
# SimpleCov::Results into a single result for coverage analysis based
# upon multiple test suites.
#
module SimpleCov
  module ResultMerger
    class << self
      # The path to the .resultset.json cache file
      def resultset_path
        File.join(SimpleCov.coverage_path, ".resultset.json")
      end

      def resultset_writelock
        File.join(SimpleCov.coverage_path, ".resultset.json.lock")
      end

      # Loads the cached resultset from JSON and returns it as a Hash,
      # caching it for subsequent accesses.
      def resultset
        @resultset ||= begin
          data = stored_data
          if data
            begin
              JSON.parse(data) || {}
            rescue
              {}
            end
          else
            {}
          end
        end
      end

      # Returns the contents of the resultset cache as a string or if the file is missing or empty nil
      def stored_data
        synchronize_resultset do
          return unless File.exist?(resultset_path)
          data = File.read(resultset_path)
          return if data.nil? || data.length < 2
          data
        end
      end

      # Gets the resultset hash and re-creates all included instances
      # of SimpleCov::Result from that.
      # All results that are above the SimpleCov.merge_timeout will be
      # dropped. Returns an array of SimpleCov::Result items.
      def results
        results = []
        resultset.each do |command_name, data|
          result = SimpleCov::Result.from_hash(command_name => data)
          # Only add result if the timeout is above the configured threshold
          if (Time.now - result.created_at) < SimpleCov.merge_timeout
            results << result
          end
        end
        results
      end

      # Merge two or more SimpleCov::Results into a new one with merged
      # coverage data and the command_name for the result consisting of a join
      # on all source result's names
      def merge_results(*results)
        merged = SimpleCov::RawCoverage.merge_results(*results.map(&:original_result))
        result = SimpleCov::Result.new(merged)
        # Specify the command name
        result.command_name = results.map(&:command_name).sort.join(", ")
        result
      end

      #
      # Gets all SimpleCov::Results from cache, merges them and produces a new
      # SimpleCov::Result with merged coverage data and the command_name
      # for the result consisting of a join on all source result's names
      #
      def merged_result
        merge_results(*results)
      end

      # Saves the given SimpleCov::Result in the resultset cache
      def store_result(result)
        synchronize_resultset do
          # Ensure we have the latest, in case it was already cached
          clear_resultset
          new_set = resultset
          command_name, data = result.to_hash.first
          new_set[command_name] = data
          File.open(resultset_path, "w+") do |f_|
            f_.puts JSON.pretty_generate(new_set)
          end
        end
        true
      end

      # Ensure only one process is reading or writing the resultset at any
      # given time
      def synchronize_resultset
        # make it reentrant
        return yield if defined?(@resultset_locked) && @resultset_locked

        begin
          @resultset_locked = true
          File.open(resultset_writelock, "w+") do |f|
            f.flock(File::LOCK_EX)
            yield
          end
        ensure
          @resultset_locked = false
        end
      end

      # Clear out the previously cached .resultset
      def clear_resultset
        @resultset = nil
      end
    end
  end
end
