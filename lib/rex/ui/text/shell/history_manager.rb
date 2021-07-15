# -*- coding: binary -*-

module Rex
module Ui
module Text
module Shell

class HistoryManager

  MAX_HISTORY = 2000

  @@contexts = []

  @@write_mutex = Mutex.new
  @@write_queue = {}

  def self.inspect
    "#<HistoryManager stack size: #{@@contexts.length}>"
  end

  def self.context_stack
    @@contexts
  end

  def self.push_context(history_file: nil, name: nil)
    dlog("HistoryManager.push_context name: #{name.inspect}")
    new_context = { history_file: history_file, name: name }

    switch_context(new_context, @@contexts.last)
    @@contexts.push(new_context)
  end

  def self.pop_context
    if @@contexts.empty?
      elog("HistoryManager.pop_context called even when the stack was already empty!")
      return
    end

    old_context = @@contexts.pop
    switch_context(@@contexts.last, old_context)

    dlog("HistoryManager.pop_context name: #{old_context&.fetch(:name, nil).inspect}")
  end

  def self.with_context(**kwargs, &block)
    push_context(**kwargs)

    begin
      block.call
    ensure
      pop_context
    end
  end

  def self.flush
    sleep 0.1 until @@write_queue.empty?
  end

  class << self
    private

    def clear_readline
      Readline::HISTORY.length.times { Readline::HISTORY.pop }
    end

    def load_history_file(history_file)
      clear_readline
      if commands = from_storage_queue(history_file)
        commands.reverse.each do |c|
          Readline::HISTORY << c
        end
      else
        if File.exist?(history_file)
          File.readlines(history_file).each do |e|
            Readline::HISTORY << e.chomp
          end
        end
      end
    end

    def store_history_file(history_file)
      cmds = []
      history_diff = Readline::HISTORY.length < MAX_HISTORY ? Readline::HISTORY.length : MAX_HISTORY
      history_diff.times do
        cmds.push(Readline::HISTORY.pop)
      end

      write_history_file(history_file, cmds)
    end

    def switch_context(new_context, old_context=nil)
      if old_context&.fetch(:history_file, nil)
        store_history_file(old_context[:history_file])
      end

      if new_context&.fetch(:history_file, nil)
        load_history_file(new_context[:history_file])
      else
        clear_readline
      end
    rescue SignalException => e
      clear_readline
    end

    def write_history_file(history_file, cmds)
      @@write_mutex.synchronize do
        @@write_queue[history_file] = cmds
      end

      Rex::ThreadFactory.spawn("#{history_file} Writer", false) do
        File.open(history_file, 'w+') do |f|
          f.puts(cmds.reverse)
        end

        @@write_mutex.synchronize do
          @@write_queue.delete(history_file)
        end
      end
    end

    def from_storage_queue(history_file)
      @@write_mutex.synchronize do
        @@write_queue[history_file]
      end
    end
  end
end

end
end
end
end
