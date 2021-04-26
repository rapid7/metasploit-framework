# -*- coding: binary -*-
module Msf
module Ui
module Console

class HistoryManager
 

  @@contexts = []

  def self.push_context(history_file)
    @@contexts.push(history_file)
    self.set_history_file(history_file)
  end

  def self.pop_context()
    cmds = []
    history_diff = Readline::HISTORY.size - @@original_histsize
    history_diff.times do 
      cmds.push(Readline::HISTORY.pop)
    end
    history_file = @@contexts.pop
    File.open(history_file, "a+") { |f| 
      f.puts(cmds.reverse) }
    Readline::HISTORY.length.times {Readline::HISTORY.pop}
  end


  def self.set_history_file(history_file)
    Readline::HISTORY.length.times {Readline::HISTORY.pop}
    if File.exist?(history_file)
    File.readlines(history_file).each { |e|
      Readline::HISTORY << e.chomp
    }
    @@original_histsize = Readline::HISTORY.size
    else
      @@original_histsize = 0
    end
  end
end

end
end
end
