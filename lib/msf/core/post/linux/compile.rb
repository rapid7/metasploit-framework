# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module Compile
        include ::Msf::Post::Common
        include ::Msf::Post::File
        include ::Msf::Post::Unix

        def initialize(info = {})
          super
          register_options([
            OptEnum.new('COMPILE', [true, 'Compile on target', 'Auto', ['Auto', 'True', 'False']]),
            OptString.new('CC', [true, 'The compiler to use', 'gcc'], conditions: ['COMPILE', 'in', ['Auto', 'True']]),
            OptString.new('MAKE', [true, 'The build system to use', 'make'], conditions: ['COMPILE', 'in', ['Auto', 'True']])
          ], self.class)
        end

        def live_compile?
          return false unless %w[Auto True].include?(datastore['COMPILE'])

          if command_exists?(datastore['CC']) || command_exists?(datastore['MAKE'])
            vprint_good "#{datastore['CC']} is installed"
            vprint_good "#{datastore['MAKE']} is installed"
            return true
          end

          unless datastore['COMPILE'] == 'Auto'
            fail_with Module::Failure::BadConfig, "#{datastore['CC']} is not installed. Set COMPILE False to upload a pre-compiled executable."
          end
        end

        # Uploads a directory and all its files and sub-directories from the host to the target,
        # and compiles the project using a build system.
        # @param _remote_path [String] The path of the directory on the target. It will be created.
        # @param localpath [String] The path of the source code to upload, on the host.
        # @param make_flags [String] command line arguments that get passed to the build system. example: "-j4"
        # make_vars [String] environment variables to define before invoking make ("CC=clang" for example).
        # premake_commands [Array] An array of strings: the commands to run before running make.
        # example array elements: "/path/to/autogen.sh", "/path/to/configure", "autoconf" etc.
        # An optional block can be given, it will receive file paths and file contents, and should return
        # the source code to upload (it can trim comments for example)
        def upload_and_make(_remote_path, localpath, make_flags='', make_vars='', premake_commands = [])
          mkdir(_remote_path)
          dirs = [ '.' ]
          until dirs.empty?
            current_dir = dirs.pop
            dir_full_path = ::File.join(localpath, current_dir)
            Dir.entries(dir_full_path).each do |ent|
              next if ent == '.' || ent == '..'

              full_path_host = ::File.join(dir_full_path, ent)
              relative_path = ::File.join(current_dir, ent)
              full_path_target = ::File.join(_remote_path, current_dir, ent)
              if ::File.file?(full_path_host)
                vprint_status("Uploading #{relative_path} to #{full_path_target}")
                file_content = ::File.read(local, mode: 'rb')
                file_content = yield(relative_path, file_content) if block_given?
                write_file(full_path_target, file_content)
              elsif ::File.directory?(full_path_host)
                vprint_status("Creating the directory #{full_path_target}")
                mkdir(full_path_target)
                dirs.push(relative_path)
              else
                print_error("#{full_path_host} doesn't look like a file or a directory")
              end
            end
          end

          premake_commands.each do |command|
            output = cmd_exec(command)
            vprint_status(output) unless output.empty?
          end

          make_command = "#{make_vars} #{datastore['MAKE']} #{make_flags}"
          output = cmd_exec(make_command)
          vprint_status(output) unless output.empty?
        end

        # Uploads and compiles a single program file.
        # @param remote_path [String] The path where to upload the file on the target.
        # @param data [String] The exploit source code.
        # @param cc_args [String] Command line arguments to pass to the compiler (-lpthread for example).
        def upload_and_compile(remote_path, data, cc_args = '', cc_vars='')
          write_file(remote_path, data)
          cc_vars = "PATH=\"$PATH:/usr/bin/\" #{cc_vars}" if session.type == 'shell'
          cc_cmd = "#{cc_vars} #{datastore['CC']} #{cc_args}"

          output = cmd_exec(cc_cmd)
          rm_f(path)
          vprint_status(output) unless output.empty?
        end

        def strip_comments(c_code)
          c_code.gsub(%r{/\*.*?\*/}m, '').gsub(%r{^\s*//.*$}, '')
        end
      end # Compile
    end # Linux
  end # Post
end # Msf
