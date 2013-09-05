# readline.rb -- GNU Readline module
# Copyright (C) 1997-2001  Shugo Maed
#
# Ruby translation by Park Heesob phasis@gmail.com

=begin
Copyright (c) 2009, Park Heesob
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Park Heesob nor the names of its contributors
  may be used to endorse or promote products derived from this software
  without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
=end

require 'windows_console_color_support'

module Readline

   require 'rbreadline'
   include RbReadline

   @completion_proc = nil
   @completion_case_fold = false

   #
   # A sneaky way to prevent the real Readline from loading after us
   #
   $LOADED_FEATURES.unshift("readline.rb")

   # Begins an interactive terminal process using +prompt+ as the command
   # prompt that users see when they type commands. The method returns the
   # line entered whenever a carriage return is encountered.
   #
   # If an +add_history+ argument is provided, commands entered by users are
   # stored in a history buffer that can be recalled for later use.
   #
   # Note that this method depends on $stdin and $stdout both being open.
   # Because this is meant as an interactive console interface, they should
   # generally not be redirected.
   #
   # Example:
   #
   #    loop{ Readline.readline('> ') }
   #
   def readline(prompt, add_history=nil)
      if $stdin.closed?
         raise IOError, "stdin closed"
      end

      status = 0

      begin
         RbReadline.rl_instream  = $stdin
         RbReadline.rl_outstream = $stdout
         if (Rex::Compat.is_windows)
            RbReadline.rl_outstream = WindowsConsoleColorSupport.new($stdout)
         end
         buff = RbReadline.readline(prompt)
      rescue ::Interrupt
         raise $!
      rescue Exception => e
         buff = nil
         RbReadline.rl_cleanup_after_signal()
         RbReadline.rl_deprep_terminal()
         $stderr.puts "[-] RbReadline Error: #{e.class} #{e} #{e.backtrace}"
     retry
      end

      if add_history && buff
         RbReadline.add_history(buff)
      end

      return buff ? buff.dup : nil
   end

   # Sets the input stream (an IO object) for readline interaction. The
   # default is <tt>$stdin</tt>.
   #
   def self.input=(input)
      RbReadline.rl_instream = input
   end

   # Sets the output stream (an IO object) for readline interaction. The
   # default is <tt>$stdout</tt>.
   #
   def self.output=(output)
      RbReadline.rl_outstream = output
   end

   # Sets the auto-completion procedure (i.e. tab auto-complete).
   #
   # The +proc+ argument is typically a Proc object. It must respond to
   # <tt>.call</tt>, take a single String argument and return an Array of
   # candidates for completion.
   #
   # Example:
   #
   #    list = ['search', 'next', 'clear']
   #    Readline.completion_proc = proc{ |s| list.grep( /^#{Regexp.escape(s)}/) }
   #
   def self.completion_proc=(proc)
      unless defined? proc.call
         raise ArgumentError,"argument must respond to `call'"
      end
      @completion_proc = proc
   end

   # Returns the current auto-completion procedure.
   #
   def self.completion_proc()
      @completion_proc
   end

   # Sets whether or not the completion proc should ignore case sensitivity.
   # The default is false, i.e. completion procs are case sensitive.
   #
   def self.completion_case_fold=(bool)
      @completion_case_fold = bool
   end

   # Returns whether or not the completion proc is case sensitive. The
   # default is false, i.e. completion procs are case sensitive.
   #
   def self.completion_case_fold()
      @completion_case_fold
   end

   def self.readline_attempted_completion_function(text,start,_end)
      proc = @completion_proc
      return nil if proc.nil?

      RbReadline.rl_attempted_completion_over = true

      # Remove leading spaces
      text.gsub!(/^\s+/, '')

      case_fold = @completion_case_fold
      ary = proc.call(text)
      if ary.class != Array
         ary = Array(ary)
      else
         ary.compact!
         ary.uniq!
      end

      ary.delete('')

      matches = ary.length
      return nil if (matches == 0)

      if(matches == 1)
        ary[0] = ary[0].strip + " "
      end

      result = Array.new(matches+2)
      for i in 0 ... matches
         result[i+1] = ary[i].dup
      end
      result[matches+1] = nil

      if(matches==1)
         result[0] = result[1].dup
      else
         i = 1
         low = 100000

         while (i < matches)
            if (case_fold)
               si = 0
               while ((c1 = result[i][si,1].downcase) &&
                  (c2 = result[i + 1][si,1].downcase))
                  break if (c1 != c2)
                  si += 1
               end
            else
               si = 0
               while ((c1 = result[i][si,1]) &&
                  (c2 = result[i + 1][si,1]))
                  break if (c1 != c2)
                  si += 1
               end
            end
            if (low > si)
               low = si
            end
            i+=1
         end
         result[0] = result[1][0,low]
      end

      result
   end

   # Sets vi editing mode.
   #
   def self.vi_editing_mode()
      RbReadline.rl_vi_editing_mode(1,0)
      nil
   end

   # Sets emacs editing mode
   #
   def self.emacs_editing_mode()
      RbReadline.rl_emacs_editing_mode(1,0)
      nil
   end

   # Sets the character that is automatically appended after the
   # Readline.completion_proc method is called.
   #
   # If +char+ is nil or empty, then a null character is used.
   #
   def self.completion_append_character=(char)
      if char.nil?
         RbReadline.rl_completion_append_character = ?\0
      elsif char.length==0
         RbReadline.rl_completion_append_character = ?\0
      else
         RbReadline.rl_completion_append_character = char[0]
      end
   end

   # Returns the character that is automatically appended after the
   # Readline.completion_proc method is called.
   #
   def self.completion_append_character()
      if RbReadline.rl_completion_append_character == ?\0
         nil
      end
      return RbReadline.rl_completion_append_character
   end

   # Sets the character string that signal a break between words for the
   # completion proc.
   #
   def self.basic_word_break_characters=(str)
      RbReadline.rl_basic_word_break_characters = str.dup
   end

   # Returns the character string that signal a break between words for the
   # completion proc. The default is " \t\n\"\\'`@$><=|&{(".
   #
   def self.basic_word_break_characters()
      if RbReadline.rl_basic_word_break_characters.nil?
         nil
      else
         RbReadline.rl_basic_word_break_characters.dup
      end
   end

   # Sets the character string that signal the start or end of a word for
   # the completion proc.
   #
   def self.completer_word_break_characters=(str)
      RbReadline.rl_completer_word_break_characters = str.dup
   end

   # Returns the character string that signal the start or end of a word for
   # the completion proc.
   #
   def self.completer_word_break_characters()
      if RbReadline.rl_completer_word_break_characters.nil?
         nil
      else
         RbReadline.rl_completer_word_break_characters.dup
      end
   end

   # Sets the list of quote characters that can cause a word break.
   #
   def self.basic_quote_characters=(str)
      RbReadline.rl_basic_quote_characters = str.dup
   end

   # Returns the list of quote characters that can cause a word break.
   # The default is "'\"" (single and double quote characters).
   #
   def self.basic_quote_characters()
      if RbReadline.rl_basic_quote_characters.nil?
         nil
      else
         RbReadline.rl_basic_quote_characters.dup
      end
   end

   # Sets the list of characters that can be used to quote a substring of
   # the line, i.e. a group of characters within quotes.
   #
   def self.completer_quote_characters=(str)
      RbReadline.rl_completer_quote_characters = str.dup
   end

   # Returns the list of characters that can be used to quote a substring
   # of the line, i.e. a group of characters inside quotes.
   #
   def self.completer_quote_characters()
      if RbReadline.rl_completer_quote_characters.nil?
         nil
      else
         RbReadline.rl_completer_quote_characters.dup
      end
   end

   # Sets the character string of one or more characters that indicate quotes
   # for the filename completion of user input.
   #
   def self.filename_quote_characters=(str)
      RbReadline.rl_filename_quote_characters = str.dup
   end

   # Returns the character string used to indicate quotes for the filename
   # completion of user input.
   #
   def self.filename_quote_characters()
      if RbReadline.rl_filename_quote_characters.nil?
         nil
      else
         RbReadline.rl_filename_quote_characters.dup
      end
   end

   # The History class encapsulates a history of all commands entered by
   # users at the prompt, providing an interface for inspection and retrieval
   # of all commands.
   class History
      extend Enumerable

      # The History class, stringified in all caps.
      #--
      # Why?
      #
      def self.to_s
         "HISTORY"
      end

      # Returns the command that was entered at the specified +index+
      # in the history buffer.
      #
      # Raises an IndexError if the entry is nil.
      #
      def self.[](index)
         if index < 0
            index += RbReadline.history_length
         end
         entry = RbReadline.history_get(RbReadline.history_base+index)
         if entry.nil?
            raise IndexError,"invalid index"
         end
         entry.line.dup
      end

      # Sets the command +str+ at the given index in the history buffer.
      #
      # You can only replace an existing entry. Attempting to create a new
      # entry will result in an IndexError.
      #
      def self.[]=(index,str)
         if index<0
            index += RbReadline.history_length
         end
         entry = RbReadline.replace_history_entry(index,str,nil)
         if entry.nil?
            raise IndexError,"invalid index"
         end
         str
      end

      # Synonym for Readline.add_history.
      #
      def self.<<(str)
         RbReadline.add_history(str)
      end

      # Pushes a list of +args+ onto the history buffer.
      #
      def self.push(*args)
         args.each do |str|
            RbReadline.add_history(str)
         end
      end

      # Internal function that removes the item at +index+ from the history
      # buffer, performing necessary duplication in the process.
      #--
      # TODO: mark private?
      #
      def self.rb_remove_history(index)
         entry = RbReadline.remove_history(index)
         if (entry)
            val = entry.line.dup
            entry = nil
            return val
         end
         nil
      end

      # Removes and returns the last element from the history buffer.
      #
      def self.pop()
         if RbReadline.history_length>0
            rb_remove_history(RbReadline.history_length-1)
         else
            nil
         end
      end

      # Removes and returns the first element from the history buffer.
      #
      def self.shift()
         if RbReadline.history_length>0
            rb_remove_history(0)
         else
            nil
         end
      end

      # Iterates over each entry in the history buffer.
      #
      def self.each()
         for i in 0 ... RbReadline.history_length
            entry = RbReadline.history_get(RbReadline.history_base + i)
            break if entry.nil?
            yield entry.line.dup
         end
         self
      end

      # Returns the length of the history buffer.
      #
      def self.length()
         RbReadline.history_length
      end

      # Synonym for Readline.length.
      #
      def self.size()
         RbReadline.history_length
      end

      # Returns a bolean value indicating whether or not the history buffer
      # is empty.
      #
      def self.empty?()
         RbReadline.history_length == 0
      end

      # Deletes an entry from the histoyr buffer at the specified +index+.
      #
      def self.delete_at(index)
         if index < 0
            i += RbReadline.history_length
         end
         if index < 0 || index > RbReadline.history_length - 1
            raise IndexError, "invalid index"
         end
         rb_remove_history(index)
      end

   end

   HISTORY = History

   # The Fcomp class provided to encapsulate typical filename completion
   # procedure. You will not typically use this directly, but will instead
   # use the Readline::FILENAME_COMPLETION_PROC.
   #
   class Fcomp
      def self.call(str)
         matches = RbReadline.rl_completion_matches(str,
         :rl_filename_completion_function)
         if (matches)
            result = []
            i = 0
            while(matches[i])
               result << matches[i].dup
               matches[i] = nil
               i += 1
            end
            matches = nil
            if (result.length >= 2)
               result.shift
            end
         else
            result = nil
         end
         return result
      end
   end

   FILENAME_COMPLETION_PROC = Fcomp

   # The Ucomp class provided to encapsulate typical filename completion
   # procedure. You will not typically use this directly, but will instead
   # use the Readline::USERNAME_COMPLETION_PROC.
   #
   # Note that this feature currently only works on Unix systems since it
   # ultimately uses the Etc module to iterate over a list of users.
   #
   class Ucomp
      def self.call(str)
         matches = RbReadline.rl_completion_matches(str,
         :rl_username_completion_function)
         if (matches)
            result = []
            i = 0
            while(matches[i])
               result << matches[i].dup
               matches[i] = nil
               i += 1
            end
            matches = nil
            if (result.length >= 2)
               result.shift
            end
         else
            result = nil
         end
         return result
      end
   end

   USERNAME_COMPLETION_PROC = Ucomp

   RbReadline.rl_readline_name = "Ruby"

   RbReadline.using_history()

   VERSION = RbReadline.rl_library_version

   module_function :readline

   RbReadline.rl_attempted_completion_function = :readline_attempted_completion_function

end

