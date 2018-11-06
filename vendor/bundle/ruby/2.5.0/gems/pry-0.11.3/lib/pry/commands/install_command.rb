class Pry
  class Command::InstallCommand < Pry::ClassCommand
    match 'install-command'
    group 'Commands'
    description 'Install a disabled command.'

    banner <<-'BANNER'
      Usage: install-command COMMAND

      Installs the gems necessary to run the given COMMAND. You will generally not
      need to run this unless told to by an error message.
    BANNER

    def process(name)
      require 'rubygems/dependency_installer' unless defined? Gem::DependencyInstaller
      command = find_command(name)

      unless command
        output.puts "Command #{ text.green(name) } is not found"
        return
      end

      if command_dependencies_met?(command.options)
        output.puts "Dependencies for #{ text.green(name) } are met. Nothing to do"
        return
      end

      output.puts "Attempting to install #{ text.green(name) } command..."
      gems_to_install = Array(command.options[:requires_gem])

      gems_to_install.each do |g|
        next if Rubygem.installed?(g)
        output.puts "Installing #{ text.green(g) } gem..."
        Rubygem.install(g)
      end

      gems_to_install.each do |g|
        begin
          require g
        rescue LoadError
          fail_msg = "Required gem #{ text.green(g) } installed but not found."
          fail_msg += " Aborting command installation\n"
          fail_msg += 'Tips: 1. Check your PATH; 2. Run `bundle update`'
          raise CommandError, fail_msg
        end
      end

      output.puts "Installation of #{ text.green(name) } successful! Type `help #{name}` for information"
    end
  end

  Pry::Commands.add_command(Pry::Command::InstallCommand)
end
