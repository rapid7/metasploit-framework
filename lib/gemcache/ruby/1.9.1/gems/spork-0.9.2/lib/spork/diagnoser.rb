# The Diagnoser hooks into load and require and keeps track of when files are required / loaded, and who loaded them.
# It's used when you run spork --diagnose
#
# = Example
#  
#  Spork::Diagnoser.install_hook!('/path/env.rb', '/path')
#  require '/path/to/env.rb'
#  Spork::Diagnoser.output_results(STDOUT)
class Spork::Diagnoser
  class << self
    def loaded_files
      @loaded_files ||= {}
    end
    
    # Installs the diagnoser hook into Kernel#require and Kernel#load
    #
    # == Parameters
    #
    # * +entry_file+ - The file that is used to load the project.  Used to filter the backtrace so anything that happens after it is hidden.
    # * +dir+ - The project directory.  Any file loaded outside of this directory will not be logged.
    def install_hook!(entry_file = nil, dir = Dir.pwd)
      @dir = File.expand_path(Dir.pwd, dir)
      @entry_file = entry_file
      
      Kernel.class_eval do
        alias :require_without_diagnoser :require
        alias :load_without_diagnoser :load
        
        def require(string)
          ::Spork::Diagnoser.add_included_file(string, caller)
          require_without_diagnoser(string)
        end
        private :require
        
        def load(string, wrap = false)
          ::Spork::Diagnoser.add_included_file(string, caller)
          load_without_diagnoser(string)
        end
        private :load
      end
    end
    
    def add_included_file(filename, callstack)
      filename = expand_filename(filename)
      return unless File.exist?(filename)
      loaded_files[filename] = filter_callstack(caller) if subdirectory?(filename)
    end
    
    # Uninstall the hook. Generally useful only for testing the Diagnoser.
    def remove_hook!
      return unless Kernel.private_instance_methods.map(&:to_sym).include?(:require_without_diagnoser)
      Kernel.class_eval do
        alias :require :require_without_diagnoser
        alias :load :load_without_diagnoser
        
        undef_method(:require_without_diagnoser)
        undef_method(:load_without_diagnoser)
      end
      true
    end
    
    # output the results of a diagnostic run.
    #
    # == Parameters
    #
    # * +stdout+ - An IO stream to output the results to.
    def output_results(stdout)
      project_prefix = Dir.pwd + "/"
      minimify = lambda { |f| f.gsub(project_prefix, '')}
      stdout.puts "- Spork Diagnosis -\n"
      stdout.puts "-- Summary --"
      stdout.puts loaded_files.keys.sort.map(&minimify)
      stdout.puts "\n\n\n"
      stdout.puts "-- Detail --"
      loaded_files.keys.sort.each do |file|
        stdout.puts "\n\n\n--- #{minimify.call(file)} ---\n"
        stdout.puts loaded_files[file].map(&minimify)
      end
    end
    
    private
      def filter_callstack(callstack, entry_file = @entry_file)
        callstack.pop until callstack.empty? || callstack.last.include?(@entry_file) if @entry_file
        callstack.map do |line|
          next if line.include?('lib/spork/diagnoser.rb')
          line.gsub!('require_without_diagnoser', 'require')
          line
        end.compact
      end
    
      def expand_filename(filename)
        ([Dir.pwd] + $:).each do |attempted_path|
          attempted_filename = File.expand_path(filename, attempted_path)
          return attempted_filename if File.file?(attempted_filename)
          attempted_filename = attempted_filename + ".rb"
          return attempted_filename if File.file?(attempted_filename)
        end
        filename
      end
    
      def subdirectory?(directory)
        File.expand_path(directory, Dir.pwd).include?(@dir)
      end
  end
end
