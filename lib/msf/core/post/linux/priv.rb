# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module Priv
        include ::Msf::Post::Common
        include ::Msf::Post::File

        #
        # Returns true if running as root, false if not.
        #
        # @return [Boolean]
        # @raise [RuntimeError] If execution fails.
        #
        def is_root?
          if command_exists?('id')
            user_id = cmd_exec('id -u')
            clean_user_id = user_id.to_s.gsub(/[^\d]/, '')
            if clean_user_id.empty?
              raise "Could not determine UID: #{user_id.inspect}"
            end

            return (clean_user_id == '0')
          end
          user = whoami
          data = cmd_exec('while read line; do echo $line; done </etc/passwd')
          data.each_line do |line|
            line = line.split(':')
            return true if line[0] == user && line[3].to_i == 0
          end
          false
        end

        #
        # Multiple functions to simulate native commands added
        #

        #
        # Creates an empty file at the specified path using the touch command
        #
        # @param new_path_file [String] the path to the new file to be created
        # @return [String] the output of the command
        #
        def touch_cmd(new_path_file)
          cmd_exec("> #{new_path_file}")
        end

        #
        # Copies the content of one file to another using a command execution
        #
        # @param origin_file [String] the path to the source file
        # @param final_file [String] the path to the destination file
        # @return [String] the output of the command
        #
        def cp_cmd(origin_file, final_file)
          file_origin = read_file(origin_file)
          cmd_exec("echo '#{file_origin}' > '#{final_file}'")
        end

        #
        # Retrieves the binary name of a process given its PID
        #
        # @param pid [Integer] the process ID
        # @return [String] the binary name of the process
        #
        def binary_of_pid(pid)
          binary = read_file("/proc/#{pid}/cmdline")
          if binary == '' # binary.empty?
            binary = read_file("/proc/#{pid}/comm")
          end
          if binary[-1] == "\n"
            binary = binary.split("\n")[0]
          end
          return binary
        end

        #
        # Generates a sequence of numbers from `first` to `last` with a given `increment`
        #
        # @param first [Integer] the starting number of the sequence
        # @param increment [Integer] the step increment between each number in the sequence
        # @param last [Integer] the ending number of the sequence
        # @return [Array<Integer>] an array containing the sequence of numbers
        #
        def seq(first, increment, last)
          result = []
          (first..last).step(increment) do |i|
            result.insert(-1, i)
          end
          return result
        end

        #
        # Returns the number of lines, words, and characters in a file
        #
        # @param file [String] the path to the file
        # @return [Array<Integer, Integer, Integer, String>] an array containing the number of lines, words, characters, and the file name
        #
        def wc_cmd(file)
          [nlines_file(file), nwords_file(file), nchars_file(file), file]
        end

        #
        # Returns the number of characters in a file
        #
        # @param file [String] the path to the file
        # @return [Integer] the number of characters in the file
        #
        def nchars_file(file)
          nchars = 0
          lines = read_file(file).split("\n")
          nchars = lines.length
          lines.each do |line|
            line.gsub(/ /, ' ' => '')
            nchars_line = line.length
            nchars += nchars_line
          end
          nchars
        end

        #
        # Returns the number of words in a file
        #
        # @param file [String] the path to the file
        # @return [Integer] the number of words in the file
        #
        def nwords_file(file)
          nwords = 0
          lines = read_file(file).split("\n")
          lines.each do |line|
            words = line.split(' ')
            nwords_line = words.length
            nwords += nwords_line
          end
          return nwords
        end

        #
        # Returns the number of lines in a file
        #
        # @param file [String] the path to the file
        # @return [Integer] the number of lines in the file
        #
        def nlines_file(file)
          lines = read_file(file).split("\n")
          nlines = lines.length
          return nlines
        end

        #
        # Returns the first `n` lines of a file
        #
        # @param file [String] the path to the file
        # @param nlines [Integer] the number of lines to return
        # @return [Array<String>] an array containing the first `n` lines of the file
        #
        def head_cmd(file, nlines)
          lines = read_file(file).split("\n")
          result = lines[0..nlines - 1]
          return result
        end

        #
        # Returns the last `n` lines of a file
        #
        # @param file [String] the path to the file
        # @param nlines [Integer] the number of lines to return
        # @return [Array<String>] an array containing the last `n` lines of the file
        #
        def tail_cmd(file, nlines)
          lines = read_file(file).split("\n")
          result = lines[-1 * nlines..]
          return result
        end

        #
        # Searches for a specific string in a file and returns the lines that contain the string
        #
        # @param file [String] the path to the file
        # @param string [String] the string to search for
        # @return [Array<String>] an array containing the lines that include the specified string
        #
        def grep_cmd(file, string)
          result = []
          lines = read_file(file).split("\n")

          lines.each do |line|
            if line.include?(string)
              result.insert(-1, line)
            end
          end
          return result
        end
      end
    end
  end
end
