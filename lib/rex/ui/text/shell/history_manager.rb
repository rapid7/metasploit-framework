# -*- coding: binary -*-

require 'singleton'
require 'reline'

module Rex
module Ui
module Text
module Shell

class HistoryManager

  MAX_HISTORY = 2000

  def initialize
    @contexts = []
    @debug = false
    # Values dequeued before work is started
    @write_queue = ::Queue.new
    # Values dequeued after work is completed
    @remaining_work = ::Queue.new
  end

  # Create a new history command context when executing the given block
  #
  # @param [String,nil] history_file The file to load and persist commands to
  # @param [String] name Human readable history context name
  # @param [Proc] block
  # @return [nil]
  def with_context(history_file: nil, name: nil, &block)
    # Default to Readline for backwards compatibility.
    push_context(history_file: history_file, name: name)

    begin
      block.call
    ensure
      pop_context
    end

    nil
  end

  # Flush the contents of the write queue to disk. Blocks synchronously.
  def flush
    until @write_queue.empty? && @remaining_work.empty?
      sleep 0.1
    end

    nil
  end

  def inspect
    "#<HistoryManager stack size: #{@contexts.length}>"
  end

  def _contexts
    @contexts
  end

  def _debug=(value)
    @debug = value
  end

  def _close
    event = { type: :close }
    @write_queue << event
    @remaining_work << event
  end

  private

  def debug?
    @debug
  end

  def push_context(history_file: nil, name: nil)
    $stderr.puts("Push context before\n#{JSON.pretty_generate(_contexts)}") if debug?
    new_context = { history_file: history_file, name: name }

    switch_context(new_context, @contexts.last)
    @contexts.push(new_context)
    $stderr.puts("Push context after\n#{JSON.pretty_generate(_contexts)}") if debug?

    nil
  end

  def pop_context
    $stderr.puts("Pop context before\n#{JSON.pretty_generate(_contexts)}") if debug?
    return if @contexts.empty?

    old_context = @contexts.pop
    $stderr.puts("Pop context after\n#{JSON.pretty_generate(_contexts)}") if debug?
    switch_context(@contexts.last, old_context)

    nil
  end

  def clear_history
    history.clear
  end

  def load_history_file(context)
    history_file = context[:history_file]

    begin
      File.open(history_file, 'rb') do |f|
        clear_history
        f.each_line(chomp: true) do |line|
          if history.last&.end_with?("\\")
            history.last.delete_suffix!("\\")
            history.last << "\n" << line
          else
            history << line
          end
        end
      end
    rescue Errno::EACCES, Errno::ENOENT => e
      elog "Failed to open history file: #{history_file} with error: #{e}"
    end
  end

  def store_history_file(context)
    history_file = context[:history_file]
    history_diff = history.length < MAX_HISTORY ? history.length : MAX_HISTORY

    cmds = []
    history_diff.times do
      entry = history.pop
      cmds << entry.scrub.split("\n").join("\\\n")
    end

    write_history_file(history_file, cmds.reverse)
  end

  def switch_context(new_context, old_context=nil)
    if old_context && old_context[:history_file]
      store_history_file(old_context)
    end

    if new_context && new_context[:history_file]
      load_history_file(new_context)
    else
      clear_history
    end
  rescue SignalException => _e
    clear_history
  end

  def write_history_file(history_file, cmds)
    write_queue_ref = @write_queue
    remaining_work_ref = @remaining_work

    @write_thread ||= Rex::ThreadFactory.spawn("HistoryManagerWriter", false) do
      while (event = write_queue_ref.pop)
        begin
          break if event[:type] == :close

          history_file = event[:history_file]
          cmds = event[:cmds]

          File.open(history_file, 'wb+') do |f|
            f.puts(cmds)
          end

        rescue => e
          elog(e)
        ensure
          remaining_work_ref.pop
        end
      end
    end

    event = { type: :write, history_file: history_file, cmds: cmds }
    @write_queue << event
    @remaining_work << event
  end

  def history
    ::Reline::HISTORY
  end
end

end
end
end
end
