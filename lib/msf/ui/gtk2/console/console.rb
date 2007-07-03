module Msf
  module Ui
    module Gtk2

      class Console

        ###
        #
        # Classic console herited from SkeletonConsole
        #
        ###
        class Shell < Msf::Ui::Gtk2::SkeletonConsole
          module InteractiveChannel

            include Rex::Ui::Interactive

            #
            # Interacts with self.
            #
            def _interact
              # If the channel has a left-side socket, then we can interact with it.
              if (self.lsock)
                self.interactive(true)

                interact_stream(self)

                self.interactive(false)
              else
                print_error("Channel #{self.cid} does not support interaction.")

                self.interacting = false
              end
            end

            #
            # Called when an interrupt is sent.
            #
            def _interrupt
              prompt_yesno("Terminate channel #{self.cid}?")
            end

            #
            # Suspends interaction with the channel.
            #
            def _suspend
              # Ask the user if they would like to background the session
              if (prompt_yesno("Background channel #{self.cid}?") == true)
                self.interactive(false)

                self.interacting = false
              end
            end

            #
            # Closes the channel like it aint no thang.
            #
            def _interact_complete
              begin
                self.interactive(false)

                self.close
              rescue IOError
              end
            end

            #
            # Reads data from local input and writes it remotely.
            #
            def _stream_read_local_write_remote(channel)
              data = user_input.gets

              self.write(data)
            end

            #
            # Reads from the channel and writes locally.
            #
            def _stream_read_remote_write_local(channel)
              data = self.lsock.sysread(16384)

              user_output.print(data)
            end

            #
            # Returns the remote file descriptor to select on
            #
            def _remote_fd(stream)
              self.lsock
            end

          end

          module Pipe
            #
            # Interacts with the supplied channel.
            #
            def interact_with_channel(channel, pipe)
              channel.extend(InteractiveChannel) unless (channel.kind_of?(InteractiveChannel) == true)
              @t_run = Thread.new do
                channel.interact(pipe, pipe)
              end
            end
          end

          def initialize(iter)
            session = iter[3]
            super(iter)

            if (session.type == "meterpreter")
              self.type = "shell"

              # TODO: use the API instead writing into the pipe
              meterconsole = Rex::Post::Meterpreter::Ui::Console.new(session)
              meterconsole.extend(Pipe)
              #send_cmd("execute -f cmd.exe -i -H")
              cmd_exec = "cmd.exe"
              cmd_args = nil
              channelized = true
              hidden = true
              from_mem = false
              dummy_exec = "cmd"
              p = session.sys.process.execute(cmd_exec, cmd_args,
              'Channelized' => channelized,
              'Hidden'      => hidden,
              'InMemory'    => (from_mem) ? dummy_exec : nil)

              @pipe = Rex::IO::BidirectionalPipe.new
              # Create a subscriber with a callback for the UI
              @pipe.create_subscriber_proc() do |data|
                self.insert_text(Rex::Text.to_utf8(data))
              end
              meterconsole.interact_with_channel(p.channel, @pipe)

            end
            #
            # Send command to bidirectionnal_pipe
            #
            def send_cmd(cmd)
              # What time is it ?
              # update_access

              # Write the command plus a newline to the input
              @pipe.write_input(cmd + "\n")
            end
          end

        end # Console::Shell

        ###
        #
        # Meterpreter Console herited from SkeletonConsole
        #
        ###
        class Meterpreter < Msf::Ui::Gtk2::SkeletonConsole

          def initialize(iter)
            # meterpreter client
            client = iter[3]

            # call the parent
            super(iter)

            # TODO: use the API instead writing into the pipe
            send_cmd("help")
          end

        end # Console::Meterpreter

      end # Console

    end
  end
end
