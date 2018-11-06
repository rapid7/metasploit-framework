class Pry
  class Command::Hist < Pry::ClassCommand
    match 'hist'
    group 'Editing'
    description 'Show and replay Readline history.'

    banner <<-'BANNER'
      Usage:   hist [--head|--tail]
               hist --all
               hist --head N
               hist --tail N
               hist --show START..END
               hist --grep PATTERN
               hist --clear
               hist --replay START..END
               hist --save [START..END] FILE
      Aliases: history

      Show and replay Readline history.
    BANNER

    def options(opt)
      opt.on :a, :all,    "Display all history"
      opt.on :H, :head,   "Display the first N items", :optional_argument => true, :as => Integer
      opt.on :T, :tail,   "Display the last N items", :optional_argument => true, :as => Integer
      opt.on :s, :show,   "Show the given range of lines", :optional_argument => true, :as => Range
      opt.on :G, :grep,   "Show lines matching the given pattern", :argument => true, :as => String
      opt.on :c, :clear , "Clear the current session's history"
      opt.on :r, :replay, "Replay a line or range of lines", :argument => true, :as => Range
      opt.on     :save,   "Save history to a file", :argument => true, :as => Range
      opt.on :e, :'exclude-pry', "Exclude Pry commands from the history"
      opt.on :n, :'no-numbers',  "Omit line numbers"
    end

    def process
      @history = find_history

      if opts.present?(:show)
        @history = @history.between(opts[:show])
      end

      if opts.present?(:grep)
        @history = @history.grep(opts[:grep])
      end

      @history = case
        when opts.present?(:head)
          @history.take_lines(1, opts[:head] || 10)
        when opts.present?(:tail)
          @history.take_lines(-(opts[:tail] || 10), opts[:tail] || 10)
        when opts.present?(:show)
          @history.between(opts[:show])
        else
          @history
        end

      if opts.present?(:'exclude-pry')
        @history = @history.select do |loc|
                     !command_set.valid_command?(loc.line)
                   end
      end

      if opts.present?(:save)
        process_save
      elsif opts.present?(:clear)
        process_clear
      elsif opts.present?(:replay)
        process_replay
      else
        process_display
      end
    end

    private

    def process_display
      unless opts.present?(:'no-numbers')
        @history = @history.with_line_numbers
      end

      _pry_.pager.open do |pager|
        @history.print_to_output(pager, true)
      end
    end

    def process_save
      case opts[:save]
      when Range
        @history = @history.between(opts[:save])

        unless args.first
          raise CommandError, "Must provide a file name."
        end

        file_name = File.expand_path(args.first)
      when String
        file_name = File.expand_path(opts[:save])
      end

      output.puts "Saving history in #{file_name}..."

      File.open(file_name, 'w') { |f| f.write(@history.raw) }

      output.puts "History saved."
    end

    def process_clear
      Pry.history.clear
      output.puts "History cleared."
    end

    def process_replay
      @history = @history.between(opts[:r])
      replay_sequence = @history.raw

      # If we met follow-up "hist" call, check for the "--replay" option
      # presence. If "hist" command is called with other options, proceed
      # further.
      check_for_juxtaposed_replay(replay_sequence)

      replay_sequence.lines.each do |line|
        _pry_.eval line, :generated => true
      end
    end

    # Checks +replay_sequence+ for the presence of neighboring replay calls.
    # @example
    #   [1] pry(main)> hist --show 46894
    #   46894: hist --replay 46675..46677
    #   [2] pry(main)> hist --show 46675..46677
    #   46675: 1+1
    #   46676: a = 100
    #   46677: hist --tail
    #   [3] pry(main)> hist --replay 46894
    #   Error: Replay index 46894 points out to another replay call: `hist -r 46675..46677`
    #   [4] pry(main)>
    #
    # @raise [Pry::CommandError] If +replay_sequence+ contains another
    #   "hist --replay" call
    # @param [String] replay_sequence The sequence of commands to be replayed
    #   (per saltum)
    # @return [Boolean] `false` if +replay_sequence+ does not contain another
    #   "hist --replay" call
    def check_for_juxtaposed_replay(replay_sequence)
      if replay_sequence =~ /\Ahist(?:ory)?\b/
        # Create *fresh* instance of Options for parsing of "hist" command.
        _slop = self.slop
        _slop.parse replay_sequence.split(' ')[1..-1]

        if _slop.present?(:r)
          replay_sequence = replay_sequence.split("\n").join('; ')
          index = opts[:r]
          index = index.min if index.min == index.max || index.max.nil?

          raise CommandError, "Replay index #{ index } points out to another replay call: `#{ replay_sequence }`"
        end
      else
        false
      end
    end

    # Finds history depending on the given switch.
    #
    # @return [Pry::Code] if it finds `--all` (or `-a`) switch, returns all
    #   entries in history. Without the switch returns only the entries from the
    #   current Pry session.
    def find_history
      h = if opts.present?(:all)
            Pry.history.to_a
          else
            Pry.history.to_a.last(Pry.history.session_line_count)
          end

      Pry::Code(Pry.history.filter(h[0..-2]))
    end
  end

  Pry::Commands.add_command(Pry::Command::Hist)
  Pry::Commands.alias_command 'history', 'hist'
end
