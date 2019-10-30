# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/post/windows/mssql'

RSpec.describe Msf::Post::Windows::MSSQL do
  let(:subject) do
    mod = double(Module.new)
    mod.extend described_class
    stubs = [ :vprint_status, :print_status, :vprint_good, :print_good,
      :print_error, :vprint_error, :print_bad, :vprint_bad, :print_warning ]
    stubs.each { |meth| allow(mod).to receive(meth) }
    allow(mod).to receive(:service_info).and_return({})
    mod
  end

  let(:running_pid) do
    6541
  end

  let(:stopped_pid) do
    0
  end

  let(:named_instance) do
    'NamedInstance'
  end

  # http://blogs.technet.com/b/fort_sql/archive/2010/05/31/list-of-sql-server-service-names.aspx
  let(:sql_server_7_display) do
    'MSSQLServer'
  end

  let(:sql_server_2000_display) do
    'MSSQLServer'
  end

  let(:sql_server_2000_named_display) do
    "MSSQL$#{named_instance}"
  end

  # Affects 7 and 2000
  let(:sql_server_analysis_services_display) do
    'MSSQLServerOLAPService'
  end

  let(:sql_server_2005_display) do
    'SQL Server (MSSQLSERVER)'
  end

  let(:sql_server_2005_named_display) do
    "MSSQLServer#{named_instance}"
  end

  let(:sql_server_2008_display) do
    'SQL Server (MSSQLSERVER)'
  end

  let(:sql_server_2008_named_display) do
    "SQL Server (#{named_instance})"
  end

  # Affects 2005/2008
  let(:sql_server_agent_display) do
    "SQL Server Agent (MSSQLServer)"
  end

  let(:stopped_2k8_sql_instance) do
    { display: sql_server_2008_display, pid: stopped_pid }
  end

  let(:running_2k8_sql_instance) do
    { display: sql_server_2008_display, pid: running_pid }
  end

  let(:running_named_2k8_sql_instance) do
    { display: sql_server_2008_named_display, pid: running_pid }
  end

  let(:stopped_named_2k8_sql_instance) do
    { display: sql_server_2008_named_display, pid: stopped_pid }
  end

  let(:running_sql_server_agent_service) do
    { display: sql_server_agent_display, pid: running_pid }
  end

  let(:running_2k5_sql_instance) do
    { display: sql_server_2005_display, pid: running_pid }
  end

  let(:running_named_2k5_sql_instance) do
    { display: sql_server_2005_named_display, pid: running_pid }
  end

  let(:running_2k_sql_instance) do
    { display: sql_server_2000_display, pid: running_pid }
  end

  let(:running_named_2k_sql_instance) do
    { display: sql_server_2000_named_display, pid: running_pid }
  end

  let(:running_7_sql_instance) do
    { display: sql_server_7_display, pid: running_pid }
  end

  let(:running_analysis_service) do
    { display: sql_server_analysis_services_display, pid: running_pid }
  end

  let(:normal_service) do
    { display: 'blah', pid: running_pid }
  end

  describe "#check_for_sqlserver" do
    let(:instance) do
      nil
    end

    context "when instance is nil" do
      it "should return nil if unable to locate any SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service)
        result = subject.check_for_sqlserver(instance)
        expect(result).to be_nil
      end

      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_2k8_sql_instance
      end

      it "shouldn't identify a non running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(stopped_2k8_sql_instance).and_yield(running_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_2k8_sql_instance
      end
    end

    context "when SQL Server 7 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_7_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_7_sql_instance
      end
    end

    context "when SQL Server 2000 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_2k_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_2k_sql_instance
      end

      it "should identify a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_named_2k_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k_sql_instance
      end
    end

    context "when SQL Server 2005 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_2k5_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_2k5_sql_instance
      end

      it "should identify a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_named_2k5_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k5_sql_instance
      end
    end

    context "when SQL Server 2008 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_2k8_sql_instance
      end

      it "should identify a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k8_sql_instance
      end
    end

    context "when instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should return nil if unable to locate any SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service)
        result = subject.check_for_sqlserver(instance)
        expect(result).to be_nil
      end

      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k8_sql_instance
      end

      it "shouldn't identify a non running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(stopped_named_2k8_sql_instance).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k8_sql_instance
      end

      it "should only identify that instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_2k8_sql_instance).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k8_sql_instance
      end
    end

    context "when SQL Server 7 and instance is supplied" do
      let(:instance) do
        'MSSQLServer'
      end

      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_7_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_7_sql_instance
      end
    end

    context "when SQL Server 2000 and instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should identify only a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service)
          .and_yield(running_2k_sql_instance).and_yield(running_named_2k_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k_sql_instance
      end
    end

    context "when SQL Server 2005 and instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should identify only a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service)
          .and_yield(running_2k5_sql_instance).and_yield(running_named_2k5_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k5_sql_instance
      end
    end

    context "when SQL Server 2008 and instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should identify only a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service)
          .and_yield(running_2k8_sql_instance).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        expect(result).to eq running_named_2k8_sql_instance
      end
    end
  end

  describe "#impersonate_sql_user" do
    let(:pid) do
      8787
    end

    let(:user) do
      'sqluser'
    end

    let(:service) do
      { pid: pid }
    end

    let(:process) do
      { 'pid' => pid, 'user' => user }
    end

    it 'should return false if service is invalid or pid is invalid' do
      expect(subject.impersonate_sql_user(nil)).to be_falsey
      expect(subject.impersonate_sql_user(pid: nil)).to be_falsey
      expect(subject.impersonate_sql_user(pid: 0)).to be_falsey
    end

    context 'user has privs to impersonate' do
      before(:example) do
        allow(subject).to receive_message_chain('session.sys.config.getuid').and_return('Superman')
        allow(subject).to receive_message_chain('client.sys.config.getprivs').and_return(['SeAssignPrimaryTokenPrivilege'])
        allow(subject).to receive_message_chain('session.sys.process.each_process').and_yield(process)
      end

      it 'should return true if successful impersonating' do
        allow(subject).to receive_message_chain('session.incognito.incognito_impersonate_token').with(user).and_return('Successfully')
        expect(subject.impersonate_sql_user(service)).to be true
      end

      it 'should return false if fails impersonating' do
        allow(subject).to receive_message_chain('session.incognito.incognito_impersonate_token').with(user).and_return('guff')
        expect(subject.impersonate_sql_user(service)).to be false
      end

      it 'should return false if unable to find process username' do
        allow(subject).to receive_message_chain('session.sys.process.each_process').and_yield('pid' => 0)
        expect(subject.impersonate_sql_user(service)).to be false
      end
    end

    context 'user does not have privs to impersonate' do
      before(:example) do
        allow(subject).to receive_message_chain('session.sys.config.getuid').and_return('Superman')
        allow(subject).to receive_message_chain('client.sys.config.getprivs').and_return([])
      end

      it 'should return true if successful' do
        expect(subject).to receive(:print_warning)
        allow(subject).to receive_message_chain('session.core.migrate').with(pid).and_return(true)
        expect(subject.impersonate_sql_user(service)).to be true
      end

      it 'should rescue an exception if migration fails' do
        expect(subject).to receive(:print_warning)
        allow(subject).to receive_message_chain('session.core.migrate').with(pid).and_raise(Rex::RuntimeError)
        expect(subject.impersonate_sql_user(service)).to be false
      end
    end
  end

  describe "#get_system" do
    it 'should return true if already SYSTEM' do
      expect(subject).to receive(:is_system?).and_return(true)
      expect(subject.get_system).to be_truthy
    end

    it 'should return true if able to get SYSTEM and print a warning' do
      expect(subject).to receive(:is_system?).and_return(false)
      expect(subject).to receive(:print_warning)
      allow(subject).to receive_message_chain('session.priv.getsystem').and_return([true])
      expect(subject.get_system).to be_truthy
    end

    it 'should return false if unable to get SYSTEM and print a warning' do
      expect(subject).to receive(:is_system?).and_return(false)
      expect(subject).to receive(:print_warning)
      allow(subject).to receive_message_chain('session.priv.getsystem').and_return([false])
      expect(subject.get_system).to be_falsey
    end
  end

  describe "#run_cmd" do
    it 'should return a string' do
      p = double('process')
      c = double('channel')
      allow(p).to receive(:channel).and_return(c)
      allow(subject).to receive_message_chain('session.sys.process.execute').and_return(p)
      expect(c).to receive(:read).and_return('hello')
      expect(c).to receive(:read).and_return(nil)
      expect(c).to receive(:close)
      expect(p).to receive(:close)
      expect(subject.run_cmd(nil)).to eq 'hello'
    end
  end

  describe "#run_sql" do
    let(:sqlclient) do
      'blah'
    end

    before(:example) do
      subject.sql_client = sqlclient
    end

    let(:query) do
      'SELECT * FROM TABLE;'
    end

    let(:instance) do
      'commandInstance'
    end

    let(:server) do
      'mssql1231'
    end

    context 'when only a query is supplied' do
      it 'should pass the @sql_client, and query to run_cmd' do
        expect(subject).to receive(:run_cmd) do |*args|
          expect(args.first.include?(sqlclient)).to be_truthy
          expect(args.first.include?("-Q \"#{query}\" ")).to be_truthy
          expect(args.first.include?("-S . ")).to be_truthy
        end
        subject.run_sql(query)
      end
    end

    context 'when a query and instance is supplied' do
      it 'should pass the @sql_client, query, and instance to run_cmd' do
        expect(subject).to receive(:run_cmd) do |*args|
          expect(args.first.include?(sqlclient)).to be_truthy
          expect(args.first.include?("-Q \"#{query}\" ")).to be_truthy
          expect(args.first.include?("-S .\\#{instance} ")).to be_truthy
        end
        subject.run_sql(query, instance)
      end

      it 'should shouldnt supply an instance if the target is mssqlserver (7/2000)' do
        expect(subject).to receive(:run_cmd) do |*args|
          expect(args.first.include?(sqlclient)).to be_truthy
          expect(args.first.include?("-Q \"#{query}\" ")).to be_truthy
          expect(args.first.include?("-S . ")).to be_truthy
        end
        subject.run_sql(query, 'mssqlsErver')
      end
    end

    context 'when a query, instance, and server is supplied' do
      it 'should pass the @sql_client, query, instance, and server to run_cmd' do
        expect(subject).to receive(:run_cmd) do |*args|
          expect(args.first.include?(sqlclient)).to be_truthy
          expect(args.first.include?("-Q \"#{query}\" ")).to be_truthy
          expect(args.first.include?("-S #{server}\\#{instance} ")).to be_truthy
        end
        subject.run_sql(query, instance, server)
      end
    end
  end

  let(:osql) do
    'osql'
  end

  let(:sql_command) do
    'sqlcmd'
  end

  describe "#check_osql" do
    it "should return nil if no osql" do
      expect(subject).to receive(:run_cmd).with('osql -?').and_return('blah')
      expect(subject.check_osql).to be_falsey
    end

    it "should return true if present" do
      expect(subject).to receive(:run_cmd).with('osql -?').and_return('(usage: osql)')
      expect(subject.check_osql).to be_truthy
    end
  end

  describe "#check_sqlcmd" do
    it "should return nil if no sqlcmd" do
      expect(subject).to receive(:run_cmd).and_return('blah')
      expect(subject.check_sqlcmd).to be_falsey
    end

    it "should return true if present" do
      expect(subject).to receive(:run_cmd).and_return('SQL Server Command Line Tool')
      expect(subject.check_sqlcmd).to be_truthy
    end
  end

  describe "#get_sql_client" do
    it "should return nil if no client is available" do
      expect(subject).to receive(:check_sqlcmd).and_return(false)
      expect(subject).to receive(:check_osql).and_return(false)
      expect(subject.get_sql_client).to be_nil
      expect(subject.sql_client).to be_nil
    end

    it "should return 'osql' if osql is available" do
      expect(subject).to receive(:check_sqlcmd).and_return(false)
      expect(subject).to receive(:check_osql).and_return(true)
      expect(subject.get_sql_client).to eq osql
      expect(subject.sql_client).to eq osql
    end

    it "should return 'sqlcmd' if sqlcmd is available" do
      allow(subject).to receive(:check_osql).and_return(true)
      expect(subject).to receive(:check_sqlcmd).and_return(true)
      expect(subject.get_sql_client).to eq sql_command
      expect(subject.sql_client).to eq sql_command
    end
  end
end
