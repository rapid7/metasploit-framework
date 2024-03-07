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
  # @param [Symbol] input_library The input library to provide context for. :reline, :readline
  # @param [Proc] block
  # @return [nil]
  def with_context(history_file: nil, name: nil, input_library: nil, &block)
    input_library ||= :readline # Default to Readline for backwards compatibility.
    push_context(history_file: history_file, name: name, input_library: input_library)

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

  def push_context(history_file: nil, name: nil, input_library: nil)
    $stderr.puts("Push context before\n#{JSON.pretty_generate(_contexts)}") if debug?
    new_context = { history_file: history_file, name: name, input_library: input_library }

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

  def reline_available?
    begin
      require 'reline'
      defined?(::Reline)
    rescue ::LoadError => _e
      false
    end
  end

  def clear_readline
    return unless readline_available?

    ::Readline::HISTORY.length.times { ::Readline::HISTORY.pop }
  end

  def clear_reline
    return unless reline_available?

    ::Reline::HISTORY.length.times { ::Reline::HISTORY.pop }
  end

  def load_history_file(context)
    history_file = context[:history_file]
    case context[:input_library]
    when :readline
      return unless readline_available?

      clear_readline
      if File.exist?(history_file)
        File.readlines(history_file).each do |e|
          ::Readline::HISTORY << safe_undump(e.chomp)
        end
      end
    when :reline
      return unless reline_available?

      clear_reline
      if File.exist?(history_file)
        File.readlines(history_file).each do |e|
          ::Reline::HISTORY << safe_undump(e.chomp)
        end
      end
    end
  end

  def store_history_file(context)
    cmds = []
    history_file = context[:history_file]

    case context[:input_library]
    when :readline
      return unless readline_available?

      history_diff = ::Readline::HISTORY.length < MAX_HISTORY ? ::Readline::HISTORY.length : MAX_HISTORY
      history_diff.times do
        entry = ::Readline::HISTORY.pop.dump
        cmds.push(entry) unless entry.nil?
      end
    when :reline
      return unless reline_available?

      history_diff = ::Reline::HISTORY.length < MAX_HISTORY ? ::Reline::HISTORY.length : MAX_HISTORY
      history_diff.times do
        entry = ::Reline::HISTORY.pop.dump
        cmds.push(entry) unless entry.nil?
      end
    end

    write_history_file(history_file, cmds)
  end

  def switch_context(new_context, old_context=nil)
    if old_context && old_context[:history_file]
      store_history_file(old_context)
    end

    if new_context && new_context[:history_file]
      load_history_file(new_context)
    else
      clear_readline
      clear_reline
    end
  rescue SignalException => _e
    clear_readline
    clear_reline
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

  # @param [String] dumped A string that has been previously dumped
  # @return [String] A string that is undumped if possible or the input if it can't be undumped.
  def safe_undump(dumped)
    begin
      dumped.undump
    rescue ::RuntimeError => _e
      dumped
    end
  end
end

end
end
end
end
