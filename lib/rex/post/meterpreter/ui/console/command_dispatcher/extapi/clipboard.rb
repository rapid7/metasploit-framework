# -*- coding: binary -*-

require 'rex/post/meterpreter'
require 'rex/post/meterpreter/extensions/extapi/command_ids'

module Rex
  module Post
    module Meterpreter
      module Ui
        ###
        #
        # Extended API window management user interface.
        #
        ###
        class Console::CommandDispatcher::Extapi::Clipboard

          Klass = Console::CommandDispatcher::Extapi::Clipboard

          include Console::CommandDispatcher
          include Rex::Post::Meterpreter::Extensions::Extapi

          #
          # List of supported commands.
          #
          def commands
            all = {
              'clipboard_get_data' => "Read the target's current clipboard (text, files, images)",
              'clipboard_set_text' => "Write text to the target's clipboard",
              'clipboard_monitor_start' => 'Start the clipboard monitor',
              'clipboard_monitor_pause' => 'Pause the active clipboard monitor',
              'clipboard_monitor_resume' => 'Resume the paused clipboard monitor',
              'clipboard_monitor_dump' => 'Dump all captured clipboard content',
              'clipboard_monitor_purge' => 'Delete all captured clipboard content without dumping it',
              'clipboard_monitor_stop' => 'Stop the clipboard monitor'
            }
            reqs = {
              'clipboard_get_data' => [COMMAND_ID_EXTAPI_CLIPBOARD_GET_DATA],
              'clipboard_set_text' => [COMMAND_ID_EXTAPI_CLIPBOARD_SET_DATA],
              'clipboard_monitor_start' => [COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_START],
              'clipboard_monitor_pause' => [COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_PAUSE],
              'clipboard_monitor_resume' => [COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_RESUME],
              'clipboard_monitor_dump' => [COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_DUMP],
              'clipboard_monitor_purge' => [COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_PURGE],
              'clipboard_monitor_stop' => [COMMAND_ID_EXTAPI_CLIPBOARD_MONITOR_STOP]
            }
            filter_commands(all, reqs)
          end

          #
          # Name for this dispatcher
          #
          def name
            'Extapi: Clipboard Management'
          end

          #
          # Options for the clipboard_get_data command.
          #
          @@get_data_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ],
            '-d' => [ true, 'Download non-text content to the specified folder (default: current dir)', nil ]
          )

          def print_clipboard_get_data_usage
            print(
              "\nUsage: clipboard_get_data [-h] [-d]\n\n" +
              "Attempts to read the data from the target's clipboard. If the data is in a\n" +
              "supported format, it is read and returned to the user.\n" +
              @@get_data_opts.usage + "\n"
            )
          end

          #
          # Get the data from the target's clipboard
          #
          def cmd_clipboard_get_data(*args)
            download_content = false
            download_path = nil
            @@get_data_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-d'
                download_content = true
                download_path = val
              when '-h'
                print_clipboard_get_data_usage
                return true
              end
            end

            dump = client.extapi.clipboard.get_data(download_content)

            if dump.length == 0
              print_error('The current Clipboard data format is not supported.')
              return false
            end

            parse_dump(dump, download_content, download_content, download_path)
            return true
          end

          #
          # Options for the clipboard_set_text command.
          #
          @@set_text_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ]
          )

          def print_clipboard_set_text_usage
            print(
              "\nUsage: clipboard_set_text [-h] <text>\n\n" +
              "Set the target's clipboard to the given text value.\n\n"
            )
          end

          #
          # Set the clipboard data to the given text.
          #
          def cmd_clipboard_set_text(*args)
            args.unshift '-h' if args.length == 0

            @@set_text_opts.parse(args) do |opt, _idx, _val|
              case opt
              when '-h'
                print_clipboard_set_text_usage
                return true
              end
            end

            return client.extapi.clipboard.set_text(args.join(' '))
          end

          #
          # Options for the clipboard_monitor_start command.
          #
          @@monitor_start_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ],
            '--no-images' => [ true, 'Do not capture image content when monitoring' ]
          )

          #
          # Help for the clipboard_monitor_start command.
          #
          def print_clipboard_monitor_start_usage
            print(
              "\nUsage: clipboard_monitor_start  [-h]\n\n" +
              "Starts a background clipboard monitoring thread. The thread watches\n" +
              "the clipboard on the target, under the context of the current desktop, and when\n" +
              "changes are detected the contents of the clipboard are captured. Contents can be\n" +
              "dumped periodically. Image content can be captured as well (and will be by default)\n" +
              "however this can consume quite a bit of memory.\n\n" +
              @@monitor_start_opts.usage + "\n"
            )
          end

          #
          # Start the clipboard monitor.
          #
          def cmd_clipboard_monitor_start(*args)
            capture_images = true

            @@monitor_start_opts.parse(args) do |opt, _idx, _val|
              case opt
              when '--no-images'
                capture_images = false
              when '-h'
                print_clipboard_monitor_start_usage
                return true
              end
            end

            client.extapi.clipboard.monitor_start({
              # random class and window name so that it isn't easy
              # to track via a script
              wincls: Rex::Text.rand_text_alpha(8),
              cap_img: capture_images
            })

            print_good('Clipboard monitor started')
          end

          #
          # Options for the clipboard_monitor_purge command.
          #
          @@monitor_purge_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ]
          )

          #
          # Help for the clipboard_monitor_purge command.
          #
          def print_clipboard_monitor_purge_usage
            print("\nUsage: clipboard_monitor_purge [-h]\n\n" +
              "Purge the captured contents from the monitor. This does not stop\n" +
              "the monitor from running, it just removes captured content.\n\n" +
              @@monitor_purge_opts.usage + "\n")
          end

          #
          # Purge the clipboard monitor captured contents
          #
          def cmd_clipboard_monitor_purge(*args)
            @@monitor_purge_opts.parse(args) do |opt, _idx, _val|
              case opt
              when '-h'
                print_clipboard_monitor_purge_usage
                return true
              end
            end
            client.extapi.clipboard.monitor_purge
            print_good('Captured clipboard contents purged successfully')
          end

          #
          # Options for the clipboard_monitor_pause command.
          #
          @@monitor_pause_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ]
          )

          #
          # Help for the clipboard_monitor_pause command.
          #
          def print_clipboard_monitor_pause_usage
            print("\nUsage: clipboard_monitor_pause [-h]\n\n" +
              "Pause the currently running clipboard monitor thread.\n\n" +
              @@monitor_pause_opts.usage + "\n")
          end

          #
          # Pause the clipboard monitor captured contents
          #
          def cmd_clipboard_monitor_pause(*args)
            @@monitor_pause_opts.parse(args) do |opt, _idx, _val|
              case opt
              when '-h'
                print_clipboard_monitor_pause_usage
                return true
              end
            end
            client.extapi.clipboard.monitor_pause
            print_good('Clipboard monitor paused successfully')
          end

          #
          # Options for the clipboard_monitor_resumse command.
          #
          @@monitor_resume_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ]
          )

          #
          # Help for the clipboard_monitor_resume command.
          #
          def print_clipboard_monitor_resume_usage
            print("\nUsage: clipboard_monitor_resume [-h]\n\n" +
              "Resume the currently paused clipboard monitor thread.\n\n" +
              @@monitor_resume_opts.usage + "\n")
          end

          #
          # resume the clipboard monitor captured contents
          #
          def cmd_clipboard_monitor_resume(*args)
            @@monitor_resume_opts.parse(args) do |opt, _idx, _val|
              case opt
              when '-h'
                print_clipboard_monitor_resume_usage
                return true
              end
            end
            client.extapi.clipboard.monitor_resume
            print_good('Clipboard monitor resumed successfully')
          end

          #
          # Options for the clipboard_monitor_dump command.
          #
          @@monitor_dump_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ],
            '--no-images' => [ false, "Indicate if captured image data shouldn't be downloaded" ],
            '--no-files' => [ false, "Indicate if captured file data shouldn't be downloaded" ],
            '--no-purge' => [ false, "Indicate if the contents of the monitor shouldn't be purged once dumped" ],
            '-d' => [ true, 'Download non-text content to the specified folder' ],
            '--force' => [false, 'Force overwriting existing files']
          )

          #
          # Help for the clipboard_monitor_dump command.
          #
          def print_clipboard_monitor_dump_usage
            print(
              "\nUsage: clipboard_monitor_dump [-d downloaddir] [-h]\n\n" +
              "Dump the capture clipboard contents to the local machine..\n\n" +
              @@monitor_dump_opts.usage + "\n"
            )
          end

          #
          # Dump the clipboard monitor contents to the local machine.
          #
          def cmd_clipboard_monitor_dump(*args)
            purge = true
            download_images = true
            download_files = true
            download_path = nil
            force_overwrite = false

            @@monitor_dump_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-d'
                download_path = val
              when '--no-images'
                download_images = false
              when '--no-files'
                download_files = false
              when '--no-purge'
                purge = false
              when '--force'
                force_overwrite = true
              when '-h'
                print_clipboard_monitor_dump_usage
                return true
              end
            end

            if download_path.nil?
              print_error('You have to specify destination directory to download loot.')
              return true
            end

            # do something with dump
            dump = client.extapi.clipboard.monitor_dump({
              include_images: download_images,
              purge: false
            })

            res = parse_dump(dump, download_images, download_files, download_path, force_overwrite: force_overwrite)
            print_good('Clipboard monitor dumped')

            if !res && purge
              client.extapi.clipboard.monitor_purge
              print_good('Captured clipboard contents purged successfully')
            end
          end

          #
          # Options for the clipboard_monitor_stop command.
          #
          @@monitor_stop_opts = Rex::Parser::Arguments.new(
            '-h' => [ false, 'Help banner' ],
            '--no-dump' => [ false, "Indicate if captured clipboard data shouldn't be dumped" ],
            '--no-images' => [ false, "Indicate if captured image data shouldn't be downloaded" ],
            '--no-files' => [ false, "Indicate if captured file data shouldn't be downloaded" ],
            '-d' => [ true, 'Download non-text content to the specified folder' ],
            '--force' => [false, 'Force overwriting existing files']
          )

          #
          # Help for the clipboard_monitor_stop command.
          #
          def print_clipboard_monitor_stop_usage
            print(
              "\nUsage: clipboard_monitor_stop [-d downloaddir] [-h]\n\n" +
              "Stops a clipboard monitor thread and returns the captured data to the local machine.\n\n" +
              @@monitor_stop_opts.usage + "\n"
            )
          end

          #
          # Stop the clipboard monitor.
          #
          def cmd_clipboard_monitor_stop(*args)
            dump_data = true
            download_images = true
            download_files = true
            download_path = nil
            force_overwrite = false

            @@monitor_stop_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-d'
                download_path = val
              when '--no-dump'
                dump_data = false
              when '--no-images'
                download_images = false
              when '--no-files'
                download_files = false
              when '--force'
                force_overwrite = true
              when '-h'
                print_clipboard_monitor_stop_usage
                return true
              end
            end

            # you can't download stuff if you don't specify destination directory
            # todo: is there more ruby way to do this
            download_images = download_images && download_path.nil? ? false : download_images

            dump = client.extapi.clipboard.monitor_stop({
              dump: dump_data,
              include_images: download_images
            })

            parse_dump(dump, download_images, download_files, download_path, force_overwrite: force_overwrite) if dump_data

            print_good('Clipboard monitor stopped')
          end

          private

          def download_file(dest_folder, source, force_overwrite = false)
            stat = client.fs.file.stat(source)
            base = ::Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File.basename(source)
            attempted_overwrite = false

            # Basename ends up with a single name/folder. This is the only point where it
            # may be possible to do a dir trav up one folder. We need to check to make sure
            # that the basename doesn't result in a traversal
            return false, attempted_overwrite if base == '..'

            local_dest_path = File.join(dest_folder, base)
            local_dest_path = ::File.expand_path(local_dest_path)

            return false, attempted_overwrite unless local_dest_path.start_with?(::File.expand_path(dest_folder) + ::File::SEPARATOR)

            if stat.directory?
              client.fs.dir.download(local_dest_path, source, { 'force_overwrite' => force_overwrite, 'recursive' => true }) do |step, src, dst|
                attempted_overwrite ||= (step == Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_SKIPPED_WOULD_OVERWRITE)

                if step == Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_SKIPPED_WOULD_OVERWRITE
                  print_line("#{Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_SKIPPED.ljust(11)} : Would overwrite existing file #{dst}")
                elsif step == Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_COMPLETED_OVERWRITTEN
                  print_line("#{Meterpreter::Extensions::Stdapi::Fs::File::STEP_COMPLETED.ljust(11)} : Overwrote existing file #{dst}")
                else
                  print_line("#{step.ljust(11)} : #{src} -> #{dst}")
                end
                client.framework.events.on_session_download(client, src, local_dest_path) if msf_loaded?
              end
            elsif stat.file?
              client.fs.file.download(local_dest_path, source, { 'force_overwrite' => force_overwrite }) do |step, src, dst|
                attempted_overwrite ||= (step == Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_SKIPPED_WOULD_OVERWRITE)

                if step == Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_SKIPPED_WOULD_OVERWRITE
                  print_line("#{Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_SKIPPED.ljust(11)} : Would overwrite existing file #{dst}")
                elsif step == Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_COMPLETED_OVERWRITTEN
                  print_line("#{Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File::STEP_COMPLETED.ljust(11)} : Overwrote existing file #{dst}")
                else
                  print_line("#{step.ljust(11)} : #{src} -> #{dst}")
                end

                client.framework.events.on_session_download(client, src, local_dest_path) if msf_loaded?
              end
            end

            return true, attempted_overwrite
          end

          def parse_dump(dump, get_images, get_files, loot_dir, force_overwrite: false)
            overwrite_attempt = false

            if (get_images || get_files) && loot_dir.nil?
              print_error('You have to specify destination directory to download loot.')
              return true
            end

            if (get_images || get_files) && !::File.directory?(loot_dir)
              ::FileUtils.mkdir_p(loot_dir)
            end

            dump.each do |ts, elements|
              elements.each do |type, v|
                title = "#{type} captured at #{ts}"
                under = '=' * title.length
                print_line(title)
                print_line(under)

                case type
                when 'Text'
                  print_line(v)

                when 'Files'
                  v.each do |f|
                    print_line("Remote Path : #{f[:name]}")
                    print_line("File size   : #{f[:size]} bytes")
                    if get_files
                      download_status, attempt = download_file(loot_dir, f[:name], force_overwrite)
                      # if once set to true, leave it true
                      overwrite_attempt ||= attempt

                      unless download_status
                        print_error("Download of #{f[:name]} failed.")
                      end
                    end
                    print_line
                  end

                when 'Image'
                  print_line("Dimensions : #{v[:width]} x #{v[:height]}")
                  if get_images and !v[:data].nil?
                    file = "#{ts.gsub(/\D+/, '')}-#{Rex::Text.rand_text_alpha(8)}.jpg"
                    path = File.join(loot_dir, file)
                    path = ::File.expand_path(path)
                    if ::File.file?(path) && !force_overwrite
                      overwrite_attempt = true
                    else
                      ::File.binwrite(path, v[:data])
                      print_line("Downloaded : #{path}")
                    end
                  end
                end
                print_line(under)
                print_line
              end
            end
            return overwrite_attempt
          end

        end
      end
    end
  end
end
