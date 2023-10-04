# -*- coding: binary -*-

require 'singleton'

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

  def readline_available?
    defined?(::Readline)
  end

  def clear_readline
    return unless readline_available?

    ::Readline::HISTORY.length.times { ::Readline::HISTORY.pop }
  end

  def load_history_file(history_file)
    return unless readline_available?

    clear_readline
    if File.exist?(history_file)
      File.readlines(history_file).each do |e|
        ::Readline::HISTORY << e.chomp
      end
    end
  end

  def store_history_file(history_file)
    return unless readline_available?
    cmds = []
    history_diff = ::Readline::HISTORY.length < MAX_HISTORY ? ::Readline::HISTORY.length : MAX_HISTORY
    history_diff.times do
      entry = ::Readline::HISTORY.pop
      cmds.push(entry) unless entry.nil?
    end

    write_history_file(history_file, cmds)
  end

  def switch_context(new_context, old_context=nil)
    if old_context && old_context[:history_file]
      store_history_file(old_context[:history_file])
    end

    if new_context && new_context[:history_file]
      load_history_file(new_context[:history_file])
    else
      clear_readline
    end
  rescue SignalException => e
    clear_readline
  end

  def write_history_file(history_file, cmds)
    write_queue_ref = @write_queue
    remaining_work_ref = @remaining_work
    @write_thread ||= Rex::ThreadFactory.spawn("HistoryManagerWriter", false) do
      while (event = write_queue_ref.pop)
        begin
          history_file = event[:history_file]
          cmds = event[:cmds]

          File.open(history_file, 'wb+') do |f|
            f.puts(cmds.reverse)
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
end

end
end
end
end
