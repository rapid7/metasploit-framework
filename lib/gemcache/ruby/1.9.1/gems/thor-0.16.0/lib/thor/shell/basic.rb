require 'tempfile'

class Thor
  module Shell
    class Basic
      attr_accessor :base
      attr_reader   :padding

      # Initialize base, mute and padding to nil.
      #
      def initialize #:nodoc:
        @base, @mute, @padding = nil, false, 0
      end

      # Mute everything that's inside given block
      #
      def mute
        @mute = true
        yield
      ensure
        @mute = false
      end

      # Check if base is muted
      #
      def mute?
        @mute
      end

      # Sets the output padding, not allowing less than zero values.
      #
      def padding=(value)
        @padding = [0, value].max
      end

      # Asks something to the user and receives a response.
      #
      # If asked to limit the correct responses, you can pass in an
      # array of acceptable answers.  If one of those is not supplied,
      # they will be shown a message stating that one of those answers
      # must be given and re-asked the question.
      #
      # ==== Example
      # ask("What is your name?")
      #
      # ask("What is your favorite Neopolitan flavor?", :limited_to => ["strawberry", "chocolate", "vanilla"])
      #
      def ask(statement, *args)
        options = args.last.is_a?(Hash) ? args.pop : {}

        options[:limited_to] ? ask_filtered(statement, options[:limited_to], *args) : ask_simply(statement, *args)
      end

      # Say (print) something to the user. If the sentence ends with a whitespace
      # or tab character, a new line is not appended (print + flush). Otherwise
      # are passed straight to puts (behavior got from Highline).
      #
      # ==== Example
      # say("I know you knew that.")
      #
      def say(message="", color=nil, force_new_line=(message.to_s !~ /( |\t)$/))
        message = message.to_s

        message = set_color(message, *color) if color

        spaces = "  " * padding

        if force_new_line
          stdout.puts(spaces + message)
        else
          stdout.print(spaces + message)
        end
        stdout.flush
      end

      # Say a status with the given color and appends the message. Since this
      # method is used frequently by actions, it allows nil or false to be given
      # in log_status, avoiding the message from being shown. If a Symbol is
      # given in log_status, it's used as the color.
      #
      def say_status(status, message, log_status=true)
        return if quiet? || log_status == false
        spaces = "  " * (padding + 1)
        color  = log_status.is_a?(Symbol) ? log_status : :green

        status = status.to_s.rjust(12)
        status = set_color status, color, true if color

        stdout.puts "#{status}#{spaces}#{message}"
        stdout.flush
      end

      # Make a question the to user and returns true if the user replies "y" or
      # "yes".
      #
      def yes?(statement, color=nil)
        !!(ask(statement, color) =~ is?(:yes))
      end

      # Make a question the to user and returns true if the user replies "n" or
      # "no".
      #
      def no?(statement, color=nil)
        !yes?(statement, color)
      end

      # Prints values in columns
      #
      # ==== Parameters
      # Array[String, String, ...]
      #
      def print_in_columns(array)
        return if array.empty?
        colwidth = (array.map{|el| el.to_s.size}.max || 0) + 2
        array.each_with_index do |value, index|
          # Don't output trailing spaces when printing the last column
          if ((((index + 1) % (terminal_width / colwidth))).zero? && !index.zero?) || index + 1 == array.length
            stdout.puts value
          else
            stdout.printf("%-#{colwidth}s", value)
          end
        end
      end

      # Prints a table.
      #
      # ==== Parameters
      # Array[Array[String, String, ...]]
      #
      # ==== Options
      # indent<Integer>:: Indent the first column by indent value.
      # colwidth<Integer>:: Force the first column to colwidth spaces wide.
      #
      def print_table(array, options={})
        return if array.empty?

        formats, indent, colwidth = [], options[:indent].to_i, options[:colwidth]
        options[:truncate] = terminal_width if options[:truncate] == true

        formats << "%-#{colwidth + 2}s" if colwidth
        start = colwidth ? 1 : 0

        colcount = array.max{|a,b| a.size <=> b.size }.size

        maximas = []

        start.upto(colcount - 1) do |index|
          maxima = array.map {|row| row[index] ? row[index].to_s.size : 0 }.max
          maximas << maxima
          if index == colcount - 1
            # Don't output 2 trailing spaces when printing the last column
            formats << "%-s"
          else
            formats << "%-#{maxima + 2}s"
          end
        end

        formats[0] = formats[0].insert(0, " " * indent)
        formats << "%s"

        array.each do |row|
          sentence = ""

          row.each_with_index do |column, index|
            maxima = maximas[index]

            if column.is_a?(Numeric)
              if index == row.size - 1
                # Don't output 2 trailing spaces when printing the last column
                f = "%#{maxima}s"
              else
                f = "%#{maxima}s  "
              end
            else
              f = formats[index]
            end
            sentence << f % column.to_s
          end

          sentence = truncate(sentence, options[:truncate]) if options[:truncate]
          stdout.puts sentence
        end
      end

      # Prints a long string, word-wrapping the text to the current width of the
      # terminal display. Ideal for printing heredocs.
      #
      # ==== Parameters
      # String
      #
      # ==== Options
      # indent<Integer>:: Indent each line of the printed paragraph by indent value.
      #
      def print_wrapped(message, options={})
        indent = options[:indent] || 0
        width = terminal_width - indent
        paras = message.split("\n\n")

        paras.map! do |unwrapped|
          unwrapped.strip.gsub(/\n/, " ").squeeze(" ").
          gsub(/.{1,#{width}}(?:\s|\Z)/){($& + 5.chr).
          gsub(/\n\005/,"\n").gsub(/\005/,"\n")}
        end

        paras.each do |para|
          para.split("\n").each do |line|
            stdout.puts line.insert(0, " " * indent)
          end
          stdout.puts unless para == paras.last
        end
      end

      # Deals with file collision and returns true if the file should be
      # overwritten and false otherwise. If a block is given, it uses the block
      # response as the content for the diff.
      #
      # ==== Parameters
      # destination<String>:: the destination file to solve conflicts
      # block<Proc>:: an optional block that returns the value to be used in diff
      #
      def file_collision(destination)
        return true if @always_force
        options = block_given? ? "[Ynaqdh]" : "[Ynaqh]"

        while true
          answer = ask %[Overwrite #{destination}? (enter "h" for help) #{options}]

          case answer
            when is?(:yes), is?(:force), ""
              return true
            when is?(:no), is?(:skip)
              return false
            when is?(:always)
              return @always_force = true
            when is?(:quit)
              say 'Aborting...'
              raise SystemExit
            when is?(:diff)
              show_diff(destination, yield) if block_given?
              say 'Retrying...'
            else
              say file_collision_help
          end
        end
      end

      # This code was copied from Rake, available under MIT-LICENSE
      # Copyright (c) 2003, 2004 Jim Weirich
      def terminal_width
        if ENV['THOR_COLUMNS']
          result = ENV['THOR_COLUMNS'].to_i
        else
          result = unix? ? dynamic_width : 80
        end
        (result < 10) ? 80 : result
      rescue
        80
      end

      # Called if something goes wrong during the execution. This is used by Thor
      # internally and should not be used inside your scripts. If something went
      # wrong, you can always raise an exception. If you raise a Thor::Error, it
      # will be rescued and wrapped in the method below.
      #
      def error(statement)
        stderr.puts statement
      end

      # Apply color to the given string with optional bold. Disabled in the
      # Thor::Shell::Basic class.
      #
      def set_color(string, *args) #:nodoc:
        string
      end

    protected

      def lookup_color(color)
        return color unless color.is_a?(Symbol)
        self.class.const_get(color.to_s.upcase)
      end

      def stdout
        $stdout
      end

      def stdin
        $stdin
      end

      def stderr
        $stderr
      end

      def is?(value) #:nodoc:
        value = value.to_s

        if value.size == 1
          /\A#{value}\z/i
        else
          /\A(#{value}|#{value[0,1]})\z/i
        end
      end

      def file_collision_help #:nodoc:
<<HELP
Y - yes, overwrite
n - no, do not overwrite
a - all, overwrite this and all others
q - quit, abort
d - diff, show the differences between the old and the new
h - help, show this help
HELP
      end

      def show_diff(destination, content) #:nodoc:
        diff_cmd = ENV['THOR_DIFF'] || ENV['RAILS_DIFF'] || 'diff -u'

        Tempfile.open(File.basename(destination), File.dirname(destination)) do |temp|
          temp.write content
          temp.rewind
          system %(#{diff_cmd} "#{destination}" "#{temp.path}")
        end
      end

      def quiet? #:nodoc:
        mute? || (base && base.options[:quiet])
      end

      # Calculate the dynamic width of the terminal
      def dynamic_width
        @dynamic_width ||= (dynamic_width_stty.nonzero? || dynamic_width_tput)
      end

      def dynamic_width_stty
        %x{stty size 2>/dev/null}.split[1].to_i
      end

      def dynamic_width_tput
        %x{tput cols 2>/dev/null}.to_i
      end

      def unix?
        RUBY_PLATFORM =~ /(aix|darwin|linux|(net|free|open)bsd|cygwin|solaris|irix|hpux)/i
      end

      def truncate(string, width)
        as_unicode do
          chars = string.chars.to_a
          if chars.length <= width
            chars.join
          else
            ( chars[0, width-3].join ) + "..."
          end
        end
      end

      if "".respond_to?(:encode)
        def as_unicode
          yield
        end
      else
        def as_unicode
          old, $KCODE = $KCODE, "U"
          yield
        ensure
          $KCODE = old
        end
      end

      def ask_simply(statement, color=nil)
        say("#{statement} ", color)
        stdin.gets.strip
      end

      def ask_filtered(statement, answer_set, *args)
        correct_answer = nil
        until correct_answer
          answer = ask_simply("#{statement} #{answer_set.inspect}", *args)
          correct_answer = answer_set.include?(answer) ? answer : nil
          answers = answer_set.map(&:inspect).join(", ")
          say("Your response must be one of: [#{answers}]. Please try again.") unless correct_answer
        end
        correct_answer
      end

    end
  end
end
