# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/post/windows/mssql'

describe Msf::Post::Windows::MSSQL do
  let(:subject) do
    mod = Module.new
    mod.extend described_class
    stubs = [ :vprint_status, :print_status, :vprint_good, :print_good, :print_error ]
    stubs.each { |meth| mod.stub(meth) }
    mod.stub(:service_info).and_return({})
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
        result.should be_nil
      end

      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_2k8_sql_instance
      end

      it "shouldn't identify a non running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(stopped_2k8_sql_instance).and_yield(running_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_2k8_sql_instance
      end
    end

    context "when SQL Server 7 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_7_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_7_sql_instance
      end
    end

    context "when SQL Server 2000 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_2k_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_2k_sql_instance
      end

      it "should identify a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_named_2k_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k_sql_instance
      end
    end

    context "when SQL Server 2005 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_2k5_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_2k5_sql_instance
      end

      it "should identify a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_named_2k5_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k5_sql_instance
      end
    end

    context "when SQL Server 2008 and instance is nil" do
      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_2k8_sql_instance
      end

      it "should identify a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_sql_server_agent_service).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k8_sql_instance
      end
    end

    context "when instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should return nil if unable to locate any SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service)
        result = subject.check_for_sqlserver(instance)
        result.should be_nil
      end

      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k8_sql_instance
      end

      it "shouldn't identify a non running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(stopped_named_2k8_sql_instance).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k8_sql_instance
      end

      it "should only identify that instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_2k8_sql_instance).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k8_sql_instance
      end
    end

    context "when SQL Server 7 and instance is supplied" do
      let(:instance) do
        'MSSQLServer'
      end

      it "should identify a running SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).and_yield(running_7_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_7_sql_instance
      end
    end

    context "when SQL Server 2000 and instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should identify only a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).
          and_yield(running_2k_sql_instance).and_yield(running_named_2k_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k_sql_instance
      end
    end

    context "when SQL Server 2005 and instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should identify only a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).
          and_yield(running_2k5_sql_instance).and_yield(running_named_2k5_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k5_sql_instance
      end
    end

    context "when SQL Server 2008 and instance is supplied" do
      let(:instance) do
        named_instance
      end

      it "should identify only a named SQL instance" do
        allow(subject).to receive(:each_service).and_yield(normal_service).and_yield(running_analysis_service).
          and_yield(running_2k8_sql_instance).and_yield(running_named_2k8_sql_instance)
        result = subject.check_for_sqlserver(instance)
        result.should eq running_named_2k8_sql_instance
      end
    end
  end

  describe "#run_cmd" do

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
      subject.check_osql.should be_falsey
    end

    it "should return true if present" do
      expect(subject).to receive(:run_cmd).with('osql -?').and_return('(usage: osql)')
      subject.check_osql.should be_truthy
    end
  end

  describe "#check_sqlcmd" do
    it "should return nil if no sqlcmd" do
      expect(subject).to receive(:run_cmd).and_return('blah')
      subject.check_sqlcmd.should be_falsey
    end

    it "should return true if present" do
      expect(subject).to receive(:run_cmd).and_return('SQL Server Command Line Tool')
      subject.check_sqlcmd.should be_truthy
    end

  end

  describe "#get_sql_client" do
    it "should return nil if no client is available" do
      expect(subject).to receive(:check_sqlcmd).and_return(false)
      expect(subject).to receive(:check_osql).and_return(false)
      subject.get_sql_client.should be_nil
      subject.sql_client.should be_nil
    end

    it "should return 'osql' if osql is available" do
      expect(subject).to receive(:check_sqlcmd).and_return(false)
      expect(subject).to receive(:check_osql).and_return(true)
      subject.get_sql_client.should eq osql
      subject.sql_client.should eq osql
    end

    it "should return 'sqlcmd' if sqlcmd is available" do
      allow(subject).to receive(:check_osql).and_return(true)
      expect(subject).to receive(:check_sqlcmd).and_return(true)
      subject.get_sql_client.should eq sql_command
      subject.sql_client.should eq sql_command
    end
  end
end
