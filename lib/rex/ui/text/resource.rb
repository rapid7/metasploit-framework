# -*- coding: binary -*-
require 'rex/ui'
require 'erb'

module Rex
module Ui
module Text

module Resource

  # Processes a resource script file for the console.
  #
  # @param path [String] Path to a resource file to run
  # @return [void]
  def load_resource(path)
    if path == '-'
      resource_file = $stdin.read
      path = 'stdin'
    elsif ::File.exist?(path)
      resource_file = ::File.read(path)
    else
      print_error("Cannot find resource script: #{path}")
      return
    end

    # Process ERB directives first
    print_status "Processing #{path} for ERB directives."
    erb = ERB.new(resource_file)
    processed_resource = erb.result(binding)

    lines = processed_resource.each_line.to_a
    bindings = {}
    while lines.length > 0

      line = lines.shift
      break if not line
      line.strip!
      next if line.length == 0
      next if line =~ /^#/

      # Pretty soon, this is going to need an XML parser :)
      # TODO: case matters for the tag and for binding names
      if line =~ /<ruby/
        if line =~ /\s+binding=(?:'(\w+)'|"(\w+)")(>|\s+)/
          bin = ($~[1] || $~[2])
          bindings[bin] = binding unless bindings.has_key? bin
          bin = bindings[bin]
        else
          bin = binding
        end
        buff = ''
        while lines.length > 0
          line = lines.shift
          break if not line
          break if line =~ /<\/ruby>/
          buff << line
        end
        if ! buff.empty?
          print_status("resource (#{path})> Ruby Code (#{buff.length} bytes)")
          begin
            eval(buff, bin)
          rescue ::Interrupt
            raise $!
          rescue ::Exception => e
            print_error("resource (#{path})> Ruby Error: #{e.class} #{e} #{e.backtrace}")
          end
        end
      else
        print_line("resource (#{path})> #{line}")
        run_single(line)
      end
    end
  end

end

end
end
end