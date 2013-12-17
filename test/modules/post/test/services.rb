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
      if results != Windows::Error::SUCCESS
        # Failed the first time, try to stop it first, then try again
        service_stop(datastore['SSERVICE'])
        results = service_start(datastore['SSERVICE'])
      end
      ret &&= (results == Windows::Error::SUCCESS)

      ret
    end
    it "should stop #{datastore["SSERVICE"]}" do
      ret = true
      results = service_stop(datastore['SSERVICE'])
      ret &&= (results == Windows::Error::SUCCESS)

      ret
    end
  end

  def test_list
    it "should list services" do
      ret = true
      results = service_list

      ret &&= results.kind_of? Array
      ret &&= results.length > 0
      ret &&= results.select{|service| service[:name] == datastore["QSERVICE"]}

      ret
    end
  end

  def test_info
    it "should return info on a given service  #{datastore["QSERVICE"]}" do
      ret = true
      results = service_info(datastore['QSERVICE'])

      ret &&= results.kind_of? Hash
      if ret
        ret &&= results.has_key? :display
        ret &&= (results[:display] == "Windows Management Instrumentation")
        ret &&= results.has_key? :starttype
        ret &&= results.has_key? :path
        ret &&= results.has_key? :startname
      end

      ret
    end
  end

  def test_create
    it "should create a service  #{datastore["NSERVICE"]}" do
      mode = case datastore["MODE"]
        when "disable"; 4
        when "manual"; 3
        when "auto"; 2
        else; 2
        end
      ret = service_create(datastore['NSERVICE'],datastore['DNAME'],datastore['BINPATH'],mode)

      ret == Windows::Error::SUCCESS
    end

    it "should return info on the newly-created service #{datastore["NSERVICE"]}" do
      ret = true
      results = service_info(datastore['NSERVICE'])

      ret &&= results.kind_of? Hash
      ret &&= results.has_key? :display
      ret &&= (results[:display] == datastore["DNAME"])
      ret &&= results.has_key? :starttype
      ret &&= (START_TYPE[results[:starttype]].downcase == datastore["MODE"])
      ret &&= results.has_key? :path
      ret &&= results.has_key? :startname

      ret
    end

    it "should delete the new service #{datastore["NSERVICE"]}" do
      ret = service_delete(datastore['NSERVICE'])

      ret == Windows::Error::SUCCESS
    end
  end

  def test_status
    it "should return status on a given service #{datastore["QSERVICE"]}" do
      ret = true
      results = service_status(datastore['QSERVICE'])

      ret &&= results.kind_of? Hash
      if ret
        ret &&= results.has_key? :state
        ret &&= (results[:state] > 0 && results[:state] < 8)
      end

      ret
    end
  end

  def test_change
    service_name = "a" << Rex::Text.rand_text_alpha(5)
    display_name = service_name

    it "should modify config on a given service #{service_name}" do
      ret = true

      results = service_create(service_name,display_name,datastore['BINPATH'],START_TYPE_DISABLED)
      ret &&= (results == Windows::Error::SUCCESS)
      results = service_status(service_name)
      ret &&= results.kind_of? Hash
      if ret
        original_display = results[:display]
        results = service_change_config(service_name, {:display => Rex::Text.rand_text_alpha(5)})
        ret &&= (results == Windows::Error::SUCCESS)

        results = service_info(service_name)
        ret &&= (results[:display] != original_display)

        service_delete(service_name)

      end

      ret
    end
  end

  def test_restart_disabled
    service_name = "a" << Rex::Text.rand_text_alpha(5)
    display_name = service_name

    it "should start a disabled service #{service_name}" do
      ret = true
      results = service_create(service_name,display_name,datastore['BINPATH'],START_TYPE_DISABLED)

      ret &&= (results == Windows::Error::SUCCESS)
      if ret
        begin
          results = service_restart(service_name)
        ensure
          service_delete(service_name)
        end
        ret &&= results
      end

      ret
    end
  end

  def test_restart_start
    service_name = datastore['SSERVICE']

    it "should restart a started service #{service_name}" do
      ret = true

      results = service_start(service_name)
      ret &&= (results == Windows::Error::SUCCESS)
      if ret
        results = service_restart(service_name)
        ret &&= results
      end

      ret
    end
  end

  def test_noaccess
    it "should raise a runtime exception if no access to service" do
      ret = false
      begin
        results = service_stop("gpsvc")
      rescue RuntimeError
        ret = true
      end

      ret
    end
  end

  def test_no_service
    it "should raise a runtime exception if services doesnt exist" do
      ret = false
      begin
        results = service_status(Rex::Text.rand_text_alpha(5))
      rescue RuntimeError
        ret = true
      end

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
