class Pry
  class Command::ShellCommand < Pry::ClassCommand
    match(/\.(.*)/)
    group 'Input and Output'
    description "All text following a '.' is forwarded to the shell."
    command_options :listing => '.<shell command>', :use_prefix => false,
                    :takes_block => true

    banner <<-'BANNER'
      Usage: .COMMAND_NAME

      All text following a "." is forwarded to the shell.

      .ls -aF
      .uname
    BANNER

    def process(cmd)
      if cmd =~ /^cd\s*(.*)/i
        process_cd parse_destination($1)
      else
        pass_block(cmd)
        if command_block
          command_block.call `#{cmd}`
        else
          _pry_.config.system.call(output, cmd, _pry_)
        end
      end
    end

    private

    def parse_destination(dest)
      return "~" if dest.empty?
      return dest unless dest == "-"
      state.old_pwd || raise(CommandError, "No prior directory available")
    end

    def process_cd(dest)
      begin
        state.old_pwd = Dir.pwd
        Dir.chdir(File.expand_path(path_from_cd_path(dest) || dest))
      rescue Errno::ENOENT
        raise CommandError, "No such directory: #{dest}"
      end
    end

    def cd_path_env
      ENV['CDPATH']
    end

    def cd_path_exists?
      cd_path_env && cd_path_env.length.nonzero?
    end

    def path_from_cd_path(dest)
      return if !(dest && cd_path_exists?) || special_case_path?(dest)

      cd_path_env.split(File::PATH_SEPARATOR).each do |path|
        if File.directory?(path) && path.split(File::SEPARATOR).last == dest
          return path
        end
      end

      return nil
    end

    def special_case_path?(dest)
      ['.', '..', '-'].include?(dest) || dest =~ /\A[#{File::PATH_SEPARATOR}~]/
    end
  end

  Pry::Commands.add_command(Pry::Command::ShellCommand)
end
