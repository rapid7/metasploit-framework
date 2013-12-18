# @note There won't be any references to these methods in the code basis because they are specifically supplied to
#  help to debug or report errors from resource scripts.
#
# Methods for producing JUnit compatible errors.
module Msf::Ui::Console::Driver::JUnit
  # Emit a new jUnit XML output file representing an error
  def junit_error(tname, ftype, data = nil)

    if not @junit_output_path
      raise RuntimeError, "No output path, call junit_setup() first"
    end

    data ||= framework.inspect.to_s

    e = REXML::Element.new("testsuite")

    c = REXML::Element.new("testcase")
    c.attributes["classname"] = "msfrc"
    c.attributes["name"]  = tname

    f = REXML::Element.new("failure")
    f.attributes["type"] = ftype

    f.text = data
    c << f
    e << c

    bname = ("msfrpc_#{tname}").gsub(/[^A-Za-z0-9\.\_]/, '')
    bname << "_" + Digest::MD5.hexdigest(tname)

    fname = ::File.join(@junit_output_path, "#{bname}.xml")
    cnt   = 0
    while ::File.exists?( fname )
      cnt  += 1
      fname = ::File.join(@junit_output_path, "#{bname}_#{cnt}.xml")
    end

    ::File.open(fname, "w") do |fd|
      fd.write(e.to_s)
    end

    print_error("Test Error: #{tname} - #{ftype} - #{data}")
  end

  # Emit a jUnit XML output file and throw a fatal exception
  def junit_fatal_error(tname, ftype, data)
    junit_error(tname, ftype, data)
    print_error("Exiting")
    run_single("exit -y")
  end

  # Emit a new jUnit XML output file representing a success
  def junit_pass(tname)

    if not @junit_output_path
      raise RuntimeError, "No output path, call junit_setup() first"
    end

    # Generate the structure of a test case run
    e = REXML::Element.new("testsuite")
    c = REXML::Element.new("testcase")
    c.attributes["classname"] = "msfrc"
    c.attributes["name"]  = tname
    e << c

    # Generate a unique name
    bname = ("msfrpc_#{tname}").gsub(/[^A-Za-z0-9\.\_]/, '')
    bname << "_" + Digest::MD5.hexdigest(tname)

    # Generate the output path, allow multiple test with the same name
    fname = ::File.join(@junit_output_path, "#{bname}.xml")
    cnt   = 0
    while ::File.exists?( fname )
      cnt  += 1
      fname = ::File.join(@junit_output_path, "#{bname}_#{cnt}.xml")
    end

    # Write to our test output location, as specified with junit_setup
    ::File.open(fname, "w") do |fd|
      fd.write(e.to_s)
    end

    print_good("Test Pass: #{tname}")
  end

  # Configure a default output path for jUnit XML output.
  #
  # @param output_path [String] path to directory on-disk.  If the path doesn't not exist it is created.
  # @return [void]
  def junit_setup(output_path)
    output_path = ::File.expand_path(output_path)

    ::FileUtils.mkdir_p(output_path)
    @junit_output_path = output_path
    @junit_error_count = 0
    print_status("Test Output: #{output_path}")

    # We need at least one test success in order to pass
    junit_pass("framework_loaded")
  end
end
