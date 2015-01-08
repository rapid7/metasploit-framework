require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/db'

describe Msf::Ui::Console::CommandDispatcher::Db do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:db) do
    described_class.new(driver)
  end

  it { is_expected.to respond_to :active? }
  it { is_expected.to respond_to :arg_host_range }
  it { is_expected.to respond_to :arg_port_range }
  it { is_expected.to respond_to :cmd_creds_help }
  it { is_expected.to respond_to :cmd_creds_tabs }
  it { is_expected.to respond_to :cmd_db_autopwn }
  it { is_expected.to respond_to :cmd_db_autopwn_help }
  it { is_expected.to respond_to :cmd_db_connect }
  it { is_expected.to respond_to :cmd_db_connect_help }
  it { is_expected.to respond_to :cmd_db_disconnect }
  it { is_expected.to respond_to :cmd_db_disconnect_help }
  it { is_expected.to respond_to :cmd_db_driver }
  it { is_expected.to respond_to :cmd_db_driver_help }
  it { is_expected.to respond_to :cmd_db_export_help }
  it { is_expected.to respond_to :cmd_db_hosts_help }
  it { is_expected.to respond_to :cmd_db_import_help }
  it { is_expected.to respond_to :cmd_db_import_tabs }
  it { is_expected.to respond_to :cmd_db_nmap }
  it { is_expected.to respond_to :cmd_db_notes }
  it { is_expected.to respond_to :cmd_db_notes_help }
  it { is_expected.to respond_to :cmd_db_rebuild_cache }
  it { is_expected.to respond_to :cmd_db_rebuild_cache_help }
  it { is_expected.to respond_to :cmd_db_services }
  it { is_expected.to respond_to :cmd_db_services_help }
  it { is_expected.to respond_to :cmd_db_status }
  it { is_expected.to respond_to :cmd_db_vulns }
  it { is_expected.to respond_to :cmd_db_vulns_help }
  it { is_expected.to respond_to :cmd_hosts }
  it { is_expected.to respond_to :cmd_hosts_help }
  it { is_expected.to respond_to :cmd_loot_help }
  it { is_expected.to respond_to :cmd_notes_help }
  it { is_expected.to respond_to :cmd_services_help }
  it { is_expected.to respond_to :cmd_vulns_help }
  it { is_expected.to respond_to :cmd_workspace_help }
  it { is_expected.to respond_to :cmd_workspace_tabs }
  it { is_expected.to respond_to :commands }
  it { is_expected.to respond_to :creds_add }
  it { is_expected.to respond_to :creds_add_non_replayable_hash }
  it { is_expected.to respond_to :creds_add_ntlm_hash }
  it { is_expected.to respond_to :creds_add_password }
  it { is_expected.to respond_to :creds_add_ssh_key }
  it { is_expected.to respond_to :creds_search }
  it { is_expected.to respond_to :db_check_driver }
  it { is_expected.to respond_to :db_connect_postgresql }
  it { is_expected.to respond_to :db_find_tools }
  it { is_expected.to respond_to :db_parse_db_uri_postgresql }
  it { is_expected.to respond_to :deprecated_commands }
  it { is_expected.to respond_to :each_host_range_chunk }
  it { is_expected.to respond_to :make_sortable }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :report_store_local }
  it { is_expected.to respond_to :set_rhosts_from_addrs }

  describe "#cmd_creds" do
    describe "add-password" do
      let(:username) { "username" }
      let(:password) { "password" }
      context "when no core exists" do
        it "should add a Core" do
          expect {
            subject.cmd_creds("add-password", username, password)
          }.to change{ Metasploit::Credential::Core.count }.by 1
        end
      end
      context "when a core already exists" do
        before(:each) do
          priv = FactoryGirl.create(:metasploit_credential_password, data: password)
          pub = FactoryGirl.create(:metasploit_credential_username, username: username)
          core = FactoryGirl.create(:metasploit_credential_core,
                                    origin: FactoryGirl.create(:metasploit_credential_origin_import),
                                    private: priv,
                                    public: pub,
                                    realm: nil,
                                    workspace: framework.db.workspace)
        end
        it "should not add a Core" do
          expect {
            subject.cmd_creds("add-password", username, password)
          }.to_not change{ Metasploit::Credential::Core.count }
        end
      end
    end
  end

  describe "#cmd_db_export" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_db_export "-h"
        @output.should =~ [
          "Usage:",
          "    db_export -f <format> [-a] [filename]",
          "    Format can be one of: xml, pwdump"
        ]
      end
    end
  end

  describe "#cmd_db_import" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_db_import "-h"
        @output.should =~ [
          "Usage: db_import <filename> [file2...]",
          "Filenames can be globs like *.xml, or **/*.xml which will search recursively",
          "Currently supported file types include:",
          "    Acunetix",
          "    Amap Log",
          "    Amap Log -m",
          "    Appscan",
          "    Burp Session XML",
          "    CI",
          "    Foundstone",
          "    FusionVM XML",
          "    IP Address List",
          "    IP360 ASPL",
          "    IP360 XML v3",
          "    Libpcap Packet Capture",
          "    Metasploit PWDump Export",
          "    Metasploit XML",
          "    Metasploit Zip Export",
          "    Microsoft Baseline Security Analyzer",
          "    NeXpose Simple XML",
          "    NeXpose XML Report",
          "    Nessus NBE Report",
          "    Nessus XML (v1)",
          "    Nessus XML (v2)",
          "    NetSparker XML",
          "    Nikto XML",
          "    Nmap XML",
          "    OpenVAS Report",
          "    OpenVAS XML",
          "    Outpost24 XML",
          "    Qualys Asset XML",
          "    Qualys Scan XML",
          "    Retina XML",
          "    Spiceworks CSV Export",
          "    Wapiti XML"
        ]
      end
    end
  end

  describe "#cmd_hosts" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_hosts "-h"
        @output.should =~ [
          "Usage: hosts [ options ] [addr1 addr2 ...]",
          "OPTIONS:",
          "  -a,--add          Add the hosts instead of searching",
          "  -d,--delete       Delete the hosts instead of searching",
          "  -c <col1,col2>    Only show the given columns (see list below)",
          "  -h,--help         Show this help information",
          "  -u,--up           Only show hosts which are up",
          "  -o <file>         Send output to a file in csv format",
          "  -R,--rhosts       Set RHOSTS from the results of the search",
          "  -S,--search       Search string to filter by",
          "Available columns: address, arch, comm, comments, created_at, cred_count, detected_arch, exploit_attempt_count, host_detail_count, info, mac, name, note_count, os_flavor, os_lang, os_name, os_sp, purpose, scope, service_count, state, updated_at, virtual_host, vuln_count"
        ]
      end
    end
  end

  describe "#cmd_loot" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_loot "-h"
        @output.should =~ [
          "Usage: loot <options>",
          " Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]",
          "  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] [-t [type]",
          "  Del: loot -d [addr1 addr2 ...]",
          "  -a,--add          Add loot to the list of addresses, instead of listing",
          "  -d,--delete       Delete *all* loot matching host and type",
          "  -f,--file         File with contents of the loot to add",
          "  -i,--info         Info of the loot to add",
          "  -t <type1,type2>  Search for a list of types",
          "  -h,--help         Show this help information",
          "  -S,--search       Search string to filter by"
        ]
      end
    end

  end

  describe "#cmd_notes" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_notes "-h"
        @output.should =~ [
          "Usage: notes [-h] [-t <type1,type2>] [-n <data string>] [-a] [addr range]",
          "  -a,--add                  Add a note to the list of addresses, instead of listing",
          "  -d,--delete               Delete the hosts instead of searching",
          "  -n,--note <data>          Set the data for a new note (only with -a)",
          "  -t <type1,type2>          Search for a list of types",
          "  -h,--help                 Show this help information",
          "  -R,--rhosts               Set RHOSTS from the results of the search",
          "  -S,--search               Regular expression to match for search",
          "  --sort <field1,field2>    Fields to sort by (case sensitive)",
          "Examples:",
          "  notes --add -t apps -n 'winzip' 10.1.1.34 10.1.20.41",
          "  notes -t smb.fingerprint 10.1.1.34 10.1.20.41",
          "  notes -S 'nmap.nse.(http|rtsp)' --sort type,output"
        ]

      end
    end

  end

  describe "#cmd_services" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_services "-h"
        @output.should =~ [
          "Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]",
          "  -a,--add          Add the services instead of searching",
          "  -d,--delete       Delete the services instead of searching",
          "  -c <col1,col2>    Only show the given columns",
          "  -h,--help         Show this help information",
          "  -s <name1,name2>  Search for a list of service names",
          "  -p <port1,port2>  Search for a list of ports",
          "  -r <protocol>     Only show [tcp|udp] services",
          "  -u,--up           Only show services which are up",
          "  -o <file>         Send output to a file in csv format",
          "  -R,--rhosts       Set RHOSTS from the results of the search",
          "  -S,--search       Search string to filter by",
          "Available columns: created_at, info, name, port, proto, state, updated_at"
        ]
      end
    end
    describe "-p" do
      before(:each) do
        host = FactoryGirl.create(:mdm_host, :workspace => framework.db.workspace, :address => "192.168.0.1")
        FactoryGirl.create(:mdm_service, :host => host, :port => 1024, name: 'Service1', proto: 'udp')
        FactoryGirl.create(:mdm_service, :host => host, :port => 1025, name: 'Service2', proto: 'tcp')
        FactoryGirl.create(:mdm_service, :host => host, :port => 1026, name: 'Service3', proto: 'udp')
      end
      it "should list services that are on a given port" do
        db.cmd_services "-p", "1024,1025"
        @output.should =~ [
          "Services",
          "========",
          "",
          "host         port  proto  name      state  info",
          "----         ----  -----  ----      -----  ----",
          "192.168.0.1  1024  udp    Service1  open   ",
          "192.168.0.1  1025  tcp    Service2  open   "
        ]
      end
    end
    describe "-np" do
      before(:each) do
        host = FactoryGirl.create(:mdm_host, :workspace => framework.db.workspace, :address => "192.168.0.1")
        FactoryGirl.create(:mdm_service, :host => host, :port => 1024)
        FactoryGirl.create(:mdm_service, :host => host, :port => 1025)
        FactoryGirl.create(:mdm_service, :host => host, :port => 1026)
      end
      it "should list services that are not on a given port" do
        skip {
          db.cmd_services "-np", "1024"

          @output.should =~ [
            "Services",
            "========",
            "",
            "host         port  proto  name  state  info",
            "----         ----  -----  ----  -----  ----",
            "192.168.0.1  1025  snmp         open   ",
            "192.168.0.1  1026  snmp         open   "
          ]
        }
      end
    end
  end

  describe "#cmd_vulns" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_vulns "-h"
        @output.should =~ [
          "Print all vulnerabilities in the database",
          "Usage: vulns [addr range]",
          "  -h,--help             Show this help information",
          "  -p,--port <portspec>  List vulns matching this port spec",
          "  -s <svc names>        List vulns matching these service names",
          "  -S,--search           Search string to filter by",
          "  -i,--info             Display Vuln Info",
          "Examples:",
          "  vulns -p 1-65536          # only vulns with associated services",
          "  vulns -p 1-65536 -s http  # identified as http on any port"
        ]
      end
    end

  end

  describe "#cmd_workspace" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_workspace "-h"
        @output.should =~ [
          "Usage:",
          "    workspace                  List workspaces",
          "    workspace [name]           Switch workspace",
          "    workspace -a [name] ...    Add workspace(s)",
          "    workspace -d [name] ...    Delete workspace(s)",
          "    workspace -r <old> <new>   Rename workspace",
          "    workspace -h               Show this help information"
        ]
      end
    end
  end
end
