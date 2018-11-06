class Pry
  class Command::BangPry < Pry::ClassCommand
    match '!pry'
    group 'Navigating Pry'
    description 'Start a Pry session on current self.'

    banner <<-'BANNER'
      Start a Pry session on current self. Also works mid multi-line expression.
    BANNER

    def process
      target.pry
    end
  end

  Pry::Commands.add_command(Pry::Command::BangPry)
end
