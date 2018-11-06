class Pry
  class Command::Version < Pry::ClassCommand
    match 'pry-version'
    group 'Misc'
    description 'Show Pry version.'

    banner <<-'BANNER'
      Show Pry version.
    BANNER

    def process
      output.puts "Pry version: #{Pry::VERSION} on Ruby #{RUBY_VERSION}."
    end
  end

  Pry::Commands.add_command(Pry::Command::Version)
end
