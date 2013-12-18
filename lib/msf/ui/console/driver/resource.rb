# Concerning resource scripts that run in the console
module Msf::Ui::Console::Driver::Resource
  #
  # Attributes
  #

  # @!attribute [rw] active_resource
  #   The active resource file being processed by the driver.
  attr_accessor :active_resource

  #
  # Methods
  #

  # Processes the resource script file for the console.
  #
  # @param path [String, nil] path from which to load the resource script.  If `nil`, loads from the default location
  #   of `msfconsole.rc` under the configuration directory.
  # @return [void]
  def load_resource(path=nil)
    path ||= File.join(Msf::Config.config_directory, 'msfconsole.rc')
    return if not ::File.readable?(path)
    resource_file = ::File.read(path)

    self.active_resource = resource_file

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

    self.active_resource = nil
  end

  # Creates the resource script file for the console.
  #
  # @param data [String] the data for the resource script.
  # @param path [String, nil] The path on-disk to save the resource script.  If `nil`, defaults to `msfconsole.rc` under
  #   the configuration directory.
  def save_resource(data, path=nil)
    path ||= File.join(Msf::Config.config_directory, 'msfconsole.rc')

    begin
      rcfd = File.open(path, 'w')
      rcfd.write(data)
      rcfd.close
    rescue ::Exception
    end
  end
end
