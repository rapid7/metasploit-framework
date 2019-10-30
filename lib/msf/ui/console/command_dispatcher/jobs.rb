# frozen_string_literal: true
# -*- coding: binary -*-

#
# Rex
#

require 'rex/ui/text/output/buffer/stdout'

module Msf
  module Ui
    module Console
      module CommandDispatcher
        #
        # {CommandDispatcher} for commands related to background jobs in Metasploit Framework.
        #
        class Jobs
          include Msf::Ui::Console::CommandDispatcher
          include Msf::Ui::Console::CommandDispatcher::Common

          @@handler_opts = Rex::Parser::Arguments.new(
            "-h" => [ false, "Help Banner"],
            "-x" => [ false, "Shut the Handler down after a session is established"],
            "-p" => [ true,  "The payload to configure the handler for"],
            "-P" => [ true,  "The RPORT/LPORT to configure the handler for"],
            "-H" => [ true,  "The RHOST/LHOST to configure the handler for"],
            "-e" => [ true,  "An Encoder to use for Payload Stage Encoding"],
            "-n" => [ true,  "The custom name to give the handler job"]
          )

          @@jobs_opts = Rex::Parser::Arguments.new(
            "-h" => [ false, "Help banner."                                   ],
            "-k" => [ true,  "Terminate jobs by job ID and/or range."         ],
            "-K" => [ false, "Terminate all running jobs."                    ],
            "-i" => [ true,  "Lists detailed information about a running job."],
            "-l" => [ false, "List all running jobs."                         ],
            "-v" => [ false, "Print more detailed info.  Use with -i and -l"  ],
            "-p" => [ true,  "Add persistence to job by job ID"               ],
            "-P" => [ false, "Persist all running jobs on restart."           ],
            "-S" => [ true,  "Row search filter."                             ]
          )

          def commands
            {
              "jobs"       => "Displays and manages jobs",
              "rename_job" => "Rename a job",
              "kill"       => "Kill a job",
              "handler"    => "Start a payload handler as job"
            }
          end

          #
          # Returns the name of the command dispatcher.
          #
          def name
            "Job"
          end

          def cmd_rename_job_help
            print_line "Usage: rename_job [ID] [Name]"
            print_line
            print_line "Example: rename_job 0 \"meterpreter HTTPS special\""
            print_line
            print_line "Rename a job that's currently active."
            print_line "You may use the jobs command to see what jobs are available."
            print_line
          end

          def cmd_rename_job(*args)
            if args.include?('-h') || args.length != 2 || args[0] !~ /^\d+$/
              cmd_rename_job_help
              return false
            end

            job_id   = args[0].to_s
            job_name = args[1].to_s

            unless framework.jobs[job_id]
              print_error("Job #{job_id} does not exist.")
              return false
            end

            # This is not respecting the Protected access control, but this seems to be the only way
            # to rename a job. If you know a more appropriate way, patches accepted.
            framework.jobs[job_id].send(:name=, job_name)
            print_status("Job #{job_id} updated")

            true
          end

          #
          # Tab completion for the rename_job command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_rename_job_tabs(_str, words)
            return [] if words.length > 1
            framework.jobs.keys
          end

          def cmd_jobs_help
            print_line "Usage: jobs [options]"
            print_line
            print_line "Active job manipulation and interaction."
            print @@jobs_opts.usage
          end

          #
          # Displays and manages running jobs for the active instance of the
          # framework.
          #
          def cmd_jobs(*args)
            # Make the default behavior listing all jobs if there were no options
            # or the only option is the verbose flag
            args.unshift("-l") if args.empty? || args == ["-v"]

            verbose = false
            dump_list = false
            dump_info = false
            kill_job = false
            job_id = nil
            job_list = nil

            # Parse the command options
            @@jobs_opts.parse(args) do |opt, _idx, val|
              case opt
              when "-v"
                verbose = true
              when "-l"
                dump_list = true
                # Terminate the supplied job ID(s)
              when "-k"
                job_list = build_range_array(val)
                kill_job = true
              when "-K"
                print_line("Stopping all jobs...")
                framework.jobs.each_key do |i|
                  framework.jobs.stop_job(i)
                end
                File.write(Msf::Config.persist_file, '') if File.writable?(Msf::Config.persist_file)
              when "-i"
                # Defer printing anything until the end of option parsing
                # so we can check for the verbose flag.
                dump_info = true
                job_id = val
              when "-p"
                job_list = build_range_array(val)
                job_list.each do |job_id|
                  add_persist_job(job_id)
                end
              when "-P"
                print_line("Making all jobs persistent ...")
                job_list = framework.jobs.map do |k,v|
                  v.jid.to_s
                end
                job_list.each do |job_id|
                  add_persist_job(job_id)
                end
              when "-S", "--search"
                search_term = val
                dump_list = true
              when "-h"
                cmd_jobs_help
                return false
              end

            end

            if dump_list
              print("\n#{Serializer::ReadableText.dump_jobs(framework, verbose)}\n")
            end
            if dump_info
              if job_id && framework.jobs[job_id.to_s]
                job = framework.jobs[job_id.to_s]
                mod = job.ctx[0]

                output  = "\n"
                output += "Name: #{mod.name}"
                output += ", started at #{job.start_time}" if job.start_time
                print_line(output)

                show_options(mod) if mod.options.has_options?

                if verbose
                  mod_opt = Serializer::ReadableText.dump_advanced_options(mod, '   ')
                  if mod_opt && !mod_opt.empty?
                    print_line("\nModule advanced options:\n\n#{mod_opt}\n")
                  end
                end
              else
                print_line("Invalid Job ID")
              end
            end

            if kill_job
              if job_list.blank?
                print_error("Please specify valid job identifier(s)")
                return false
              end

              print_status("Stopping the following job(s): #{job_list.join(', ')}")

              # Remove  the persistent job when match the option of payload.
              begin
                persist_list = JSON.parse(File.read(Msf::Config.persist_file))
              rescue Errno::ENOENT, JSON::ParserError
                persist_list = []
              end

              # Remove persistence by job id.
              job_list.map(&:to_s).each do |job|
                if framework.jobs.key?(job)
                  next unless framework.jobs[job.to_s].ctx[1] # next if no payload context in the job
                  payload_option = framework.jobs[job.to_s].ctx[1].datastore
                  persist_list.delete_if{|pjob|pjob['mod_options']['Options'] == payload_option}
                end
              end
              # Write persist job back to config file.
              File.open(Msf::Config.persist_file,"w") do |file|
                file.puts(JSON.pretty_generate(persist_list))
              end

              # Stop the job by job id.
              job_list.map(&:to_s).each do |job|
                if framework.jobs.key?(job)
                  print_status("Stopping job #{job}")
                  framework.jobs.stop_job(job)
                else
                  print_error("Invalid job identifier: #{job}")
                end
              end
            end

          end

          #
          # Add a persistent job by job id.
          # Persistent job would restore on console restarted.

          def add_persist_job(job_id)
            if job_id && framework.jobs.has_key?(job_id.to_s)
              unless framework.jobs[job_id.to_s].ctx[1]
                print_error("Add persistent job failed: job #{job_id} is not payload handler.")
                return
              end

              mod     = framework.jobs[job_id.to_s].ctx[0].replicant
              payload = framework.jobs[job_id.to_s].ctx[1].replicant

              payload_opts = {
                'Payload'        => payload.refname,
                'Options'        => payload.datastore,
                'RunAsJob'       => true
              }

              mod_opts =  {
                'mod_name'       => mod.fullname,
                'mod_options'    => payload_opts
              }

              begin
                persist_list = JSON.parse(File.read(Msf::Config.persist_file))
              rescue Errno::ENOENT, JSON::ParserError
                persist_list = []
              end
              persist_list << mod_opts
              File.open(Msf::Config.persist_file,"w") do |file|
                file.puts(JSON.pretty_generate(persist_list))
              end
              print_line("Added persistence to job #{job_id}.")
            else
              print_line("Invalid Job ID")
            end
          end

          #
          # Tab completion for the jobs command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_jobs_tabs(_str, words)
            return @@jobs_opts.fmt.keys if words.length == 1

            if words.length == 2 && (@@jobs_opts.fmt[words[1]] || [false])[0]
              return framework.jobs.keys
            end

            []
          end

          def cmd_kill_help
            print_line "Usage: kill <job1> [job2 ...]"
            print_line
            print_line "Equivalent to 'jobs -k job1 -k job2 ...'"
          end

          def cmd_kill(*args)
            cmd_jobs("-k", *args)
          end

          #
          # Tab completion for the kill command
          #
          # @param str [String] the string currently being typed before tab was hit
          # @param words [Array<String>] the previously completed words on the command line.  words is always
          # at least 1 when tab completion has reached this stage since the command itself has been completed

          def cmd_kill_tabs(_str, words)
            return [] if words.length > 1
            framework.jobs.keys
          end

          def cmd_handler_help
            print_line "Usage: handler [options]"
            print_line
            print_line "Spin up a Payload Handler as background job."
            print @@handler_opts.usage
          end

          # Allows the user to setup a payload handler as a background job from a single command.
          def cmd_handler(*args)
            # Display the help banner if no arguments were passed
            if args.empty?
              cmd_handler_help
              return
            end

            exit_on_session     = false
            payload_module      = nil
            port                = nil
            host                = nil
            job_name            = nil
            stage_encoder       = nil

            # Parse the command options
            @@handler_opts.parse(args) do |opt, _idx, val|
              case opt
              when "-x"
                exit_on_session = true
              when "-p"
                payload_module = framework.payloads.create(val)
                if payload_module.nil?
                  print_error "Invalid Payload Name Supplied!"
                  return
                end
              when "-P"
                port = val
              when "-H"
                host = val
              when "-n"
                job_name = val
              when "-e"
                encoder_module = framework.encoders.create(val)
                if encoder_module.nil?
                  print_error "Invalid Encoder Name Supplied"
                end
                stage_encoder = encoder_module.refname
              when "-h"
                cmd_handler_help
                return
              end
            end

            # If we are missing any of the required options, inform the user about each
            # missing options, and not just one. Then exit so they can try again.
            print_error "You must select a payload with -p <payload>" if payload_module.nil?
            print_error "You must select a port(RPORT/LPORT) with -P <port number>" if port.nil?
            print_error "You must select a host(RHOST/LHOST) with -H <hostname or address>" if host.nil?
            if payload_module.nil? || port.nil? || host.nil?
              print_error "Please supply missing arguments and try again."
              return
            end

            handler = framework.modules.create('exploit/multi/handler')
            payload_datastore = payload_module.datastore

            # Set The RHOST or LHOST for the payload
            if payload_datastore.has_key? "LHOST"
              payload_datastore['LHOST'] = host
            elsif payload_datastore.has_key? "RHOST"
              payload_datastore['RHOST'] = host
            else
              print_error "Could not determine how to set Host on this payload..."
              return
            end

            # Set the RPORT or LPORT for the payload
            if payload_datastore.has_key? "LPORT"
              payload_datastore['LPORT'] = port
            elsif payload_datastore.has_key? "RPORT"
              payload_datastore['RPORT'] = port
            else
              print_error "Could not determine how to set Port on this payload..."
              return
            end

            # Set StageEncoder if selected
            if stage_encoder.present?
              payload_datastore["EnableStageEncoding"] = true
              payload_datastore["StageEncoder"] = stage_encoder
            end

            # Merge payload datastore options into the handler options
            handler_opts = {
              'Payload'        => payload_module.refname,
              'LocalInput'     => driver.input,
              'LocalOutput'    => driver.output,
              'ExitOnSession'  => exit_on_session,
              'RunAsJob'       => true
            }

            handler.datastore.reverse_merge!(payload_datastore)
            handler.datastore.merge!(handler_opts)

            # Launch our Handler and get the Job ID
            handler.exploit_simple(handler_opts)
            job_id = handler.job_id

            # Customise the job name if the user asked for it
            if job_name.present?
              framework.jobs[job_id.to_s].send(:name=, job_name)
            end

            print_status "Payload handler running as background job #{job_id}."
          end

          def cmd_handler_tabs(str, words)
            fmt = {
              '-h' => [ nil                                               ],
              '-x' => [ nil                                               ],
              '-p' => [ framework.payloads.map { |refname, mod| refname } ],
              '-P' => [ true                                              ],
              '-H' => [ :address                                          ],
              '-e' => [ framework.encoders.map { |refname, mod| refname } ],
              '-n' => [ true                                              ]
            }
            tab_complete_generic(fmt, str, words)
          end

        end
      end
    end
  end
end
