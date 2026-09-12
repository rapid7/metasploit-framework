# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/thread_factory'

module Rex
module Post
module Meterpreter

###
#
# Thread-safe store for tracking asynchronously dispatched commands
# and their results. Used when async mode is enabled to allow
# queuing multiple commands without blocking the console.
#
###
class AsyncResultStore

  # Entry states
  STATUS_PENDING   = :pending
  STATUS_RUNNING   = :running
  STATUS_COMPLETE  = :complete
  STATUS_ERROR     = :error
  STATUS_CANCELLED = :cancelled

  def initialize
    @results = {}
    @mutex = ::Mutex.new
    @work_queue = ::Queue.new
    @worker = nil
    @worker_mutex = ::Mutex.new
  end

  #
  # Enqueue a unit of work to be executed serially by the worker thread.
  # The worker is started lazily on first enqueue. The provided block is
  # invoked in the worker with (rid, label) and is responsible for calling
  # {#complete} or {#error} when done.
  #
  # @param rid [String] the request ID
  # @param label [String] human-readable command label
  # @yieldparam rid [String]
  # @yieldparam label [String]
  # @return [void]
  #
  def enqueue_work(rid, label, &executor)
    @worker_mutex.synchronize do
      raise 'Async worker is stopping' if @stopping

      queue(rid, label)
      ensure_worker_started_locked
      @work_queue.push([rid, label, executor])
    end
  end

  #
  # Ensure the worker thread is running.
  #
  # @return [void]
  #
  def ensure_worker_started
    @worker_mutex.synchronize do
      ensure_worker_started_locked
    end
  end

  #
  # Cancel pending work and stop the worker.
  # Safe to call even if the worker was never started.
  #
  # @return [void]
  #
  def stop_worker
    worker = nil
    @worker_mutex.synchronize do
      return unless @worker

      unless @worker.alive?
        @worker = nil
        return
      end

      @stopping = true
      worker = @worker

      begin
        loop do
          item = @work_queue.pop(true)
          cancel(item[0], 'Cancelled before execution') unless item == :stop
        end
      rescue ::ThreadError
        nil
      end

      @work_queue.push(:stop)
    end

    cancel_running('Cancelled while running')

    unless worker.equal?(::Thread.current)
      worker.join(5)
      if worker.alive?
        worker[:msf_async_forced_stop] = true
        worker.kill
        worker.join
      end
    end

    @worker_mutex.synchronize do
      @worker = nil
      @stopping = false
    end
  end

  #
  # Register a command as pending delivery.
  #
  # @param rid [String] the request ID
  # @param label [String] human-readable command label (e.g. "ls /tmp")
  # @return [void]
  #
  def queue(rid, label)
    @mutex.synchronize do
      @results[rid] = {
        label: label,
        status: STATUS_PENDING,
        queued_at: ::Time.now,
        started_at: nil,
        completed_at: nil,
        response: nil,
        output: nil
      }
    end
  end

  #
  # Mark a queued command as currently running (worker picked it up).
  #
  # @param rid [String] the request ID
  # @return [void]
  #
  def mark_running(rid)
    @mutex.synchronize do
      return unless @results.key?(rid)

      @results[rid][:status] = STATUS_RUNNING
      @results[rid][:started_at] = ::Time.now
    end
  end

  #
  # Mark a command as complete with its response.
  #
  # @param rid [String] the request ID
  # @param response [Rex::Post::Meterpreter::Packet, nil] the response packet
  # @param output [String, nil] captured console output
  # @return [void]
  #
  def complete(rid, response, output = nil)
    @mutex.synchronize do
      return unless @results.key?(rid)
      return if @results[rid][:status] == STATUS_CANCELLED

      @results[rid][:status] = STATUS_COMPLETE
      @results[rid][:completed_at] = ::Time.now
      @results[rid][:response] = response
      @results[rid][:output] = output
    end
  end

  #
  # Mark a command as errored.
  #
  # @param rid [String] the request ID
  # @param error_message [String] the error description
  # @return [void]
  #
  def error(rid, error_message)
    @mutex.synchronize do
      return unless @results.key?(rid)
      return if @results[rid][:status] == STATUS_CANCELLED

      @results[rid][:status] = STATUS_ERROR
      @results[rid][:completed_at] = ::Time.now
      @results[rid][:output] = error_message
    end
  end

  def cancel(rid, message = 'Cancelled')
    @mutex.synchronize do
      return unless @results.key?(rid)

      @results[rid][:status] = STATUS_CANCELLED
      @results[rid][:completed_at] = ::Time.now
      @results[rid][:output] = message
    end
  end

  #
  # Return all pending entries.
  #
  # @return [Hash] rid => entry hash
  #
  def pending
    @mutex.synchronize do
      @results.select { |_rid, entry| entry[:status] == STATUS_PENDING }
    end
  end

  #
  # Return all completed entries.
  #
  # @return [Hash] rid => entry hash
  #
  def completed
    @mutex.synchronize do
      @results.select { |_rid, entry| entry[:status] == STATUS_COMPLETE }
    end
  end

  #
  # Return all entries regardless of status.
  #
  # @return [Hash] rid => entry hash
  #
  def all
    @mutex.synchronize do
      @results.dup
    end
  end

  #
  # Fetch a specific result by rid.
  #
  # @param rid [String] the request ID
  # @return [Hash, nil] the entry or nil if not found
  #
  def fetch(rid)
    @mutex.synchronize do
      @results[rid]&.dup
    end
  end

  #
  # Remove a specific entry.
  #
  # @param rid [String] the request ID
  # @return [void]
  #
  def delete(rid)
    @mutex.synchronize do
      @results.delete(rid)
    end
  end

  #
  # Clear all completed and errored entries.
  #
  # @return [Integer] number of entries cleared
  #
  def clear_completed
    @mutex.synchronize do
      before = @results.size
      terminal = [STATUS_COMPLETE, STATUS_ERROR, STATUS_CANCELLED]
      @results.reject! { |_rid, entry| terminal.include?(entry[:status]) }
      before - @results.size
    end
  end

  #
  # Return the total number of tracked entries.
  #
  # @return [Integer]
  #
  def size
    @mutex.synchronize do
      @results.size
    end
  end

  private

  def ensure_worker_started_locked
    return if @worker && @worker.alive?

    @worker = Rex::ThreadFactory.spawn('AsyncCommandWorker', false) do
      loop do
        item = @work_queue.pop
        break if item == :stop

        rid, label, executor = item
        execute = @worker_mutex.synchronize do
          if @stopping
            cancel(rid, 'Cancelled before execution')
            false
          else
            mark_running(rid)
            true
          end
        end
        next unless execute

        short = rid[0..7]
        started = ::Time.now
        begin
          dlog("async worker: picked up #{short} (#{label.inspect})", 'meterpreter/async')
          executor.call(rid)
          elapsed = (::Time.now - started).round(1)
          dlog("async worker: completed #{short} in #{elapsed}s", 'meterpreter/async')
        rescue ::StandardError => e
          elapsed = (::Time.now - started).round(1)
          elog("async worker: #{short} raised #{e.class} after #{elapsed}s: #{e.message}", 'meterpreter/async', error: e)
          error(rid, "#{e.class}: #{e.message}")
        end
      end
    end
  end

  def cancel_running(message)
    running_ids = @mutex.synchronize do
      @results.select { |_rid, entry| entry[:status] == STATUS_RUNNING }.keys
    end
    running_ids.each { |rid| cancel(rid, message) }
  end

end

end
end
end
