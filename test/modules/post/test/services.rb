#
# by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)
#

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/services'

$:.push "test/lib" unless $:.include? "test/lib"
require 'module_test'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Services

  include Msf::ModuleTest::PostTest

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Test Post::Windows::Services',
        'Description'   => %q{ This module will test windows services methods within a shell},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'kernelsmith', 'egypt' ],
        'Version'       => '$Revision: 11663 $',
        'Platform'      => [ 'windows' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
      ))
    register_options(
      [
        OptString.new("QSERVICE" , [true, "Service (keyname) to query", "winmgmt"]),
        OptString.new("NSERVICE" , [true, "New Service (keyname) to create/del", "testes"]),
        OptString.new("SSERVICE" , [true, "Service (keyname) to start/stop", "W32Time"]),
        OptString.new("DNAME" , [true, "Display name used for create test", "Cool display name"]),
        OptString.new("BINPATH" , [true, "Binary path for create test", "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs"]),
        OptEnum.new("MODE", [true, "Mode to use for startup/create tests", "auto",
            ["auto", "manual", "disable"]
          ]),
      ], self.class)

  end

  def test_start
    it "should start #{datastore["SSERVICE"]}" do
      ret = true
      results = service_start(datastore['SSERVICE'])
      if results != 0
        # Failed the first time, try to stop it first, then try again
        service_stop(datastore['SSERVICE'])
        results = service_start(datastore['SSERVICE'])
      end
      ret &&= (results == 0)

      ret
    end
    it "should stop #{datastore["SSERVICE"]}" do
      ret = true
      results = service_stop(datastore['SSERVICE'])
      ret &&= (results == 0)

      ret
    end
  end

  def test_list
    it "should list services" do
      ret = true
      results = service_list

      ret &&= results.kind_of? Array
      ret &&= results.length > 0
      ret &&= results.include? datastore["QSERVICE"]

      ret
    end
  end

  def test_info
    it "should return info on a given service" do
      ret = true
      results = service_info(datastore['QSERVICE'])

      ret &&= results.kind_of? Hash
      if ret
        ret &&= results.has_key? "Name"
        ret &&= (results["Name"] == "Windows Management Instrumentation")
        ret &&= results.has_key? "Startup"
        ret &&= results.has_key? "Command"
        ret &&= results.has_key? "Credentials"
      end

      ret
    end
  end

  def test_create
    it "should create a service" do
      mode = case datastore["MODE"]
        when "disable"; 4
        when "manual"; 3
        when "auto"; 2
        else; 2
        end
      ret = service_create(datastore['NSERVICE'],datastore['DNAME'],datastore['BINPATH'],mode)

      ret
    end

    it "should return info on the newly-created service" do
      ret = true
      results = service_info(datastore['NSERVICE'])

      ret &&= results.kind_of? Hash
      ret &&= results.has_key? "Name"
      ret &&= (results["Name"] == datastore["DNAME"])
      ret &&= results.has_key? "Startup"
      ret &&= (results["Startup"].downcase == datastore["MODE"])
      ret &&= results.has_key? "Command"
      ret &&= results.has_key? "Credentials"

      ret
    end

    it "should delete the new service" do
      ret = service_delete(datastore['NSERVICE'])

      ret
    end
  end


=begin
  def run
    blab = datastore['VERBOSE']
    print_status("Running against session #{datastore["SESSION"]}")
    print_status("Session type is #{session.type}")
    print_status("Verbosity is set to #{blab.to_s}")
    print_status("Don't be surprised to see some errors as the script is faster")
    print_line("than the windows SCM, just make sure the errors are sane.  You can")
    print_line("set VERBOSE to true to see more details")

    print_status()
    print_status("TESTING service_query_ex on servicename: #{datastore["QSERVICE"]}")
    results = service_query_ex(datastore['QSERVICE'])
    print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

    print_status()
    print_status("TESTING service_query_config on servicename: #{datastore["QSERVICE"]}")
    results = service_query_config(datastore['QSERVICE'])
    print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

    print_status()
    print_status("TESTING service_change_startup on servicename: #{datastore['QSERVICE']} " +
          "to #{datastore['MODE']}")
    results = service_change_startup(datastore['QSERVICE'],datastore['MODE'])
    print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
    print_status("Current status of this service " +
          "#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab

    print_status()
    print_status("TESTING service_start on servicename: #{datastore['SSERVICE']}")
    results = service_start(datastore['SSERVICE'])
    print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
    print_status("Current status of this service " +
          "#{service_query_ex(datastore['SSERVICE']).pretty_inspect}") if blab
    print_status("Sleeping to give the service a chance to start")
    select(nil, nil, nil, 2) # give the service time to start, reduces false negatives

    print_status()
    print_status("TESTING service_stop on servicename: #{datastore['SSERVICE']}")
    results = service_stop(datastore['SSERVICE'])
    print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
    print_status("Current status of this service " +
          "#{service_query_ex(datastore['SSERVICE']).pretty_inspect}") if blab

    print_status()
    print_status("TESTING service_delete on servicename: #{datastore['NSERVICE']}")
    results = service_delete(datastore['NSERVICE'])
    print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
    print_status("Current status of this service " +
          "#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab
    print_status()
    print_status("Testing complete.")
  end
=end

end
