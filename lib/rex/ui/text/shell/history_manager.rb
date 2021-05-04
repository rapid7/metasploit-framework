# -*- coding: binary -*-

module Rex
module Ui
module Text
module Shell

class HistoryManager

  @@contexts = [{:history_file => Msf::Config.history_file, :name => :msfconsole}]

  def self.inspect
    "#<HistoryManager stack size: #{@@contexts.length}>"
  end

  def self.context_stack
    @@contexts
  end

  def self.push_context(history_file: nil, name: nil)
    clear_readline
    @@contexts.push({:history_file => history_file, :name => name})
    if history_file
      self.set_history_file(history_file)
    end
  end

  def self.pop_context
    if @@contexts.empty?
      elog("`#pop_context' called even when the stack was already empty!")
      return
    end
    history_file, name = @@contexts.pop.values
    if history_file
      cmds = []
      history_diff = Readline::HISTORY.size - @@original_histsize
      history_diff.times do
        cmds.push(Readline::HISTORY.pop)
      end
      File.open(history_file, 'a+') do |f|
        f.puts(cmds.reverse)
      end
    end
    clear_readline
  end

  class << self
    private

    def set_history_file(history_file)
      clear_readline
      if File.exist?(history_file)
        File.readlines(history_file).each do |e|
          Readline::HISTORY << e.chomp
        end
        @@original_histsize = Readline::HISTORY.size
      else
        @@original_histsize = 0
      end
    end

    def clear_readline
      Readline::HISTORY.length.times { Readline::HISTORY.pop }
    end

  end
end

end
end
end
end
