# -*- coding: binary -*-

require 'singleton'

module Rex
module Ui
module Text
module Shell

class HistoryManager

  include Singleton

  MAX_HISTORY = 2000

  def initialize
    @contexts = []
    @write_mutex = Mutex.new
    @write_queue = {}
    @debug = false
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
    sleep 0.1 until @write_queue.empty?

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
    commands = from_storage_queue(history_file)
    if commands
      commands.reverse.each do |c|
        ::Readline::HISTORY << c
      end
    else
      if File.exist?(history_file)
        File.readlines(history_file).each do |e|
          ::Readline::HISTORY << e.chomp
        end
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
    entry_added = false
    until entry_added
      @write_mutex.synchronize do
        if @write_queue[history_file].nil?
          @write_queue[history_file] = cmds
          entry_added = true
        end
      end
      sleep 0.1 if !entry_added
    end

    Rex::ThreadFactory.spawn("#{history_file} Writer", false) do
      File.open(history_file, 'wb+') do |f|
        f.puts(cmds.reverse)
      end

      @write_mutex.synchronize do
        @write_queue.delete(history_file)
      end
    end
  end

  def from_storage_queue(history_file)
    @write_mutex.synchronize do
      @write_queue[history_file]
    end
  end
end

end
end
end
end
