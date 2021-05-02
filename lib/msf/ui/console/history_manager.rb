# -*- coding: binary -*-

module Msf
module Ui
module Console

class HistoryManager
 

  @@contexts = [{"history_file" => Msf::Config.history_file, "set_history" => false}]
  
  def self.inspect
    "#<HistoryManager stack size: #{@@contexts.length}>"
  end

  def self.context_stack
    @@contexts
  end

  def self.push_context(history_file, set_history = false)
    @@contexts.push({"history_file" => history_file, "set_history" => set_history})
    if set_history
      self.set_history_file(history_file)
    end
  end

  def self.pop_context
    if @@contexts.empty?
      return
    end
    history_file, set_history = @@contexts.pop.values
    if set_history
      cmds = []
      history_diff = Readline::HISTORY.size - @@original_histsize
      history_diff.times do 
        cmds.push(Readline::HISTORY.pop)
      end
      File.open(history_file, "a+") { |f| 
        f.puts(cmds.reverse) }
    end
    self.clear_readline
  end


  def self.set_history_file(history_file)
    self.clear_readline
    if File.exist?(history_file)
      File.readlines(history_file).each { |e|
        Readline::HISTORY << e.chomp
      }
      @@original_histsize = Readline::HISTORY.size
    else
      @@original_histsize = 0
    end
  end

  def self.clear_readline
    Readline::HISTORY.length.times {Readline::HISTORY.pop}
  end
end

end
end
end
