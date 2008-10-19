module Msf
  module Ui
    module Gtk2

      class Stdapi

        ###
        #
        # The file system portion of the standard API extension.
        #
        ###
        class Fs < Msf::Ui::Gtk2::SkeletonBrowser
          COL_TYPE, COL_PATH, COL_DISPLAY_NAME, COL_IS_DIR, COL_PIXBUF = (0..5).to_a

          def initialize(client)

            # The session
            @client = client

            local = File.join(driver.config_directory, "logs", "sessions")
            remote = @client.fs.dir.getwd

            # call the parent
            super("msfbrowser on #{@client.tunnel_peer}", local, remote)

            # Populate the view
            create_dir_session()
            local_ls
            remote_ls
          end

          #
          # Return files widgets specified by the given directory on the remote machine
          #
          def remote_ls(*args)
            # Try to list the remote path
            begin
              # Just ignore the invalid UTF8
              # Don't know why GLib.filename_to_utf8() don't work ;-(
              ic = Iconv.new('UTF-8//IGNORE', 'UTF-8')

              self.model_remote.clear
              path = args[0] || @client.fs.dir.getwd
              path = self.dirname_meter(path)
              self.remote_path.set_text(path)

              # Enumerate each item...
              @client.fs.dir.entries_with_info(path).sort { |a,b| a['FileName'] <=> b['FileName'] }.each do |p|
                if p['StatBuf'].ftype[0,3] == "dir"
                  is_dir = true
                elsif p['StatBuf'].ftype[0,3] == "fil"
                  is_dir = false
                end
                iter = self.model_remote.append
                iter[COL_DISPLAY_NAME] = ic.iconv(p['FileName'] + ' ')[0..-2] || 'unknown'
                iter[COL_PATH] = path
                iter[COL_IS_DIR] = is_dir
                iter[COL_PIXBUF] = is_dir ? self.folder_pixbuf : self.file_pixbuf
                iter[COL_TYPE] = "remote"
              end
              self.parent_remote = path

              # If not possible return a *warning*
            rescue ::Exception => e
              MsfDialog::Warning.new(self, "Remote browser", e.to_s)
              remote_ls
            end
          end # remote_ls

          #
          # Create a directory per session
          #
          def create_dir_session
            begin
              Dir.mkdir(File.join(parent_local, @client.tunnel_peer.to_s.split(":")[0]))
            rescue
              nil
            end
          end

          #
          # Downloads a file or directory from the remote machine to the local
          # machine.
          #
          def cmd_download(*args)

            recursive = true
            src_items = args
            dest = self.parent_local

            begin
              # If there is no destination, assume it's the same as the source.
              if (!dest)
                dest = src_items[0]
              end

              # Go through each source item and download them
              src_items.each { |src|
                stat = @client.fs.file.stat(src)

                if (stat.directory?)
                  @client.fs.dir.download(dest, src, recursive) { |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  }
                elsif (stat.file?)
                  @client.fs.file.download(dest, src) { |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  }
                end
              }

            rescue ::Exception => e
              MsfDialog::Warning.new(self, "Operation failed", e.to_s)
            end

            return true
          end #cmd_download

          #
          # Uploads a file or directory to the remote machine from the local
          # machine.
          #
          def cmd_upload(*args)

            recursive = true
            src_items = args
            dest = self.parent_remote

            begin
              # If there is no destination, assume it's the same as the source.
              if (!dest)
                dest = src_items[0]
              end

              # Go through each source item and upload them
              src_items.each do |src|
                stat = ::File.stat(src)

                if (stat.directory?)
                  @client.fs.dir.upload(dest, src, recursive) do |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  end
                elsif (stat.file?)
                  @client.fs.file.upload(dest, src) do |step, src, dst|
                    $gtk2driver.append_log_view("#{step.ljust(11)}: #{src} -> #{dst}\n")
                  end
                end
              end
              
            rescue ::Exception => e
              MsfDialog::Warning.new(self, "Upload: Operation failed", e.to_s)
            end

            return true
          end # cmd_upload

        end # Fs

      end

    end
  end
end