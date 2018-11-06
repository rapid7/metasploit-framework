class Pry
  # The History class is responsible for maintaining the user's input history,
  # both internally and within Readline.
  class History
    attr_accessor :loader, :saver, :pusher, :clearer

    # @return [Fixnum] Number of lines in history when Pry first loaded.
    attr_reader :original_lines

    def initialize(options={})
      @history = []
      @original_lines = 0
      @file_path = options[:file_path]
      restore_default_behavior
    end

    # Assign the default methods for loading, saving, pushing, and clearing.
    def restore_default_behavior
      Pry.config.input # force Readline to load if applicable

      @loader = method(:read_from_file)
      @saver  = method(:save_to_file)

      if defined?(Readline)
        @pusher  = method(:push_to_readline)
        @clearer = method(:clear_readline)
      else
        @pusher  = proc { }
        @clearer = proc { }
      end
    end

    # Load the input history using `History.loader`.
    # @return [Integer] The number of lines loaded
    def load
      @loader.call do |line|
        @pusher.call(line.chomp)
        @history << line.chomp
        @original_lines += 1
      end
    end

    # Add a line to the input history, ignoring blank and duplicate lines.
    # @param [String] line
    # @return [String] The same line that was passed in
    def push(line)
      unless line.empty? || (@history.last && line == @history.last)
        @pusher.call(line)
        @history << line
        if !should_ignore?(line) && Pry.config.history.should_save
          @saver.call(line)
        end
      end
      line
    end
    alias << push

    # Clear this session's history. This won't affect the contents of the
    # history file.
    def clear
      @clearer.call
      @original_lines = 0
      @history = []
    end

    # @return [Fixnum] The number of lines in history.
    def history_line_count
      @history.count
    end

    # @return [Fixnum] The number of lines in history from just this session.
    def session_line_count
      @history.count - @original_lines
    end

    # Return an Array containing all stored history.
    # @return [Array<String>] An Array containing all lines of history loaded
    #   or entered by the user in the current session.
    def to_a
      @history.dup
    end

    # Filter the history with the histignore options
    # @return [Array<String>] An array containing all the lines that are not
    #   included in the histignore.
    def filter(history)
      history.select { |l| l unless should_ignore?(l) }
    end

    private

    # Check if the line match any option in the histignore
    # [Pry.config.history.histignore]
    # @return [Boolean] a boolean that notifies if the line was found in the
    #   histignore array.
    def should_ignore?(line)
      hist_ignore = Pry.config.history.histignore
      return false if hist_ignore.nil? || hist_ignore.empty?

      hist_ignore.any? { |p| line.to_s.match(p) }
    end

    # The default loader. Yields lines from `Pry.history.config.file`.
    def read_from_file
      path = history_file_path

      if File.exist?(path)
        File.foreach(path) { |line| yield(line) }
      end
    rescue => error
      warn "History file not loaded: #{error.message}"
    end

    # The default pusher. Appends the given line to Readline::HISTORY.
    # @param [String] line
    def push_to_readline(line)
      Readline::HISTORY << line
    end

    # The default clearer. Clears Readline::HISTORY.
    def clear_readline
      Readline::HISTORY.shift until Readline::HISTORY.empty?
    end

    # The default saver. Appends the given line to `Pry.history.config.file`.
    def save_to_file(line)
      history_file.puts line if history_file
    end

    # The history file, opened for appending.
    def history_file
      if defined?(@history_file)
        @history_file
      else
        @history_file = File.open(history_file_path, 'a', 0600).tap do |file|
          file.sync = true
        end
      end
    rescue Errno::EACCES
      warn 'History not saved; unable to open your history file for writing.'
      @history_file = false
    end

    def history_file_path
      File.expand_path(@file_path || Pry.config.history.file)
    end
  end
end
