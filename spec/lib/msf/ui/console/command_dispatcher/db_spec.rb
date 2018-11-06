require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/db'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Db do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:db) do
    described_class.new(driver)
  end

  it { is_expected.to respond_to :active? }
  it { is_expected.to respond_to :arg_host_range }
  it { is_expected.to respond_to :arg_port_range }
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
  it { is_expected.to respond_to :db_check_driver }
  it { is_expected.to respond_to :db_connect_postgresql }
  it { is_expected.to respond_to :db_find_tools }
  it { is_expected.to respond_to :db_parse_db_uri_postgresql }
  it { is_expected.to respond_to :deprecated_commands }
  it { is_expected.to respond_to :each_host_range_chunk }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :set_rhosts_from_addrs }

  describe "#cmd_db_export" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_db_export "-h"
        expect(@output).to match_array [
          "Usage:",
          "    db_export -f <format> [filename]",
          "    Format can be one of: xml, pwdump"
        ]
      end
    end
  end

  describe "#cmd_db_import" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_db_import "-h"
        expect(@output).to match_array [
          "Usage: db_import <filename> [file2...]",
          "Filenames can be globs like *.xml, or **/*.xml which will search recursively",
          "Currently supported file types include:",
          "    Acunetix",
          "    Amap Log",
          "    Amap Log -m",
          "    Appscan",
          "    Burp Issue XML",
          "    Burp Session XML",
          "    CI",
          "    Foundstone",
          "    FusionVM XML",
          "    Group Policy Preferences Credentials",
          "    IP Address List",
          "    IP360 ASPL",
          "    IP360 XML v3",
          "    Libpcap Packet Capture",
          "    Masscan XML",
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
        expect(@output).to match_array [
          "Usage: hosts [ options ] [addr1 addr2 ...]",
          "OPTIONS:",
          "  -a,--add          Add the hosts instead of searching",
          "  -d,--delete       Delete the hosts instead of searching",
          "  -c <col1,col2>    Only show the given columns (see list below)",
          "  -C <col1,col2>    Only show the given columns until the next restart (see list below)",
          "  -h,--help         Show this help information",
          "  -u,--up           Only show hosts which are up",
          "  -o <file>         Send output to a file in csv format",
          "  -O <column>       Order rows by specified column number",
          "  -R,--rhosts       Set RHOSTS from the results of the search",
          "  -S,--search       Search string to filter by",
          "  -i,--info         Change the info of a host",
          "  -n,--name         Change the name of a host",
          "  -m,--comment      Change the comment of a host",
          "  -t,--tag          Add or specify a tag to a range of hosts",
          "Available columns: address, arch, comm, comments, created_at, cred_count, detected_arch, exploit_attempt_count, host_detail_count, info, mac, name, note_count, os_family, os_flavor, os_lang, os_name, os_sp, purpose, scope, service_count, state, updated_at, virtual_host, vuln_count, tags"
        ]
      end
    end
  end

  describe "#cmd_loot" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_loot "-h"
        expect(@output).to match_array [
          "Usage: loot [options]",
          " Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]",
          "  Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] -t [type]",
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
        expect(@output).to match_array [
          "Usage: notes [-h] [-t <type1,type2>] [-n <data string>] [-a] [addr range]",
          "  -a,--add                  Add a note to the list of addresses, instead of listing",
          "  -d,--delete               Delete the hosts instead of searching",
          "  -n,--note <data>          Set the data for a new note (only with -a)",
          "  -t,--type <type1,type2>   Search for a list of types, or set single type for add",
          "  -h,--help                 Show this help information",
          "  -R,--rhosts               Set RHOSTS from the results of the search",
          "  -S,--search               Search string to filter by",
          "  -o,--output               Save the notes to a csv file",
          "  -O <column>               Order rows by specified column number",
          "Examples:",
          "  notes --add -t apps -n 'winzip' 10.1.1.34 10.1.20.41",
          "  notes -t smb.fingerprint 10.1.1.34 10.1.20.41",
          "  notes -S 'nmap.nse.(http|rtsp)'"
        ]

      end
    end

  end

  describe "#cmd_services" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_services "-h"
        expect(@output).to match_array [
          "Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]",
          "  -a,--add          Add the services instead of searching",
          "  -d,--delete       Delete the services instead of searching",
          "  -c <col1,col2>    Only show the given columns",
          "  -h,--help         Show this help information",
          "  -s <name>         Name of the service to add",
          "  -p <port>         Search for a list of ports",
          "  -r <protocol>     Protocol type of the service being added [tcp|udp]",
          "  -u,--up           Only show services which are up",
          "  -o <file>         Send output to a file in csv format",
          "  -O <column>       Order rows by specified column number",
          "  -R,--rhosts       Set RHOSTS from the results of the search",
          "  -S,--search       Search string to filter by",
          "  -U,--update       Update data for existing service",
          "Available columns: created_at, info, name, port, proto, state, updated_at"
        ]
      end
    end
    describe "-p" do
      before(:example) do
        @services = []
        @services << framework.db.report_service({host: '192.168.0.1', port: 1024, name: 'service1', proto: 'udp'})
        @services << framework.db.report_service({host: '192.168.0.1', port: 1025, name: 'service2', proto: 'tcp'})
        @services << framework.db.report_service({host: '192.168.0.1', port: 1026, name: 'service3', proto: 'udp'})
      end

      after(:example) do
        ids = []
        @services.each{|service|
          ids << service.id
        }

        framework.db.delete_service({ids: ids})
      end

      it "should list services that are on a given port" do
        db.cmd_services "-p", "1024, 1025"
        expect(@output).to match_array [
          "Services",
          "========",
          "",
          "host         port  proto  name      state  info",
          "----         ----  -----  ----      -----  ----",
          "192.168.0.1  1024  udp    service1  open   ",
          "192.168.0.1  1025  tcp    service2  open   "
        ]
      end
    end

    describe "-np" do
      before(:example) do
        @services = []
        @services << framework.db.report_service({host: '192.168.0.2', port: 1024})
        @services << framework.db.report_service({host: '192.168.0.2', port: 1025})
        @services << framework.db.report_service({host: '192.168.0.2', port: 1026})
      end

      after(:example) do
        ids = []
        @services.each{|service|
          ids << service.id
        }

        framework.db.delete_service({ids: ids})
      end

      it "should list services that are not on a given port" do
        skip {
          db.cmd_services "-np", "1024"

          expect(@output).to =~ [
            "Services",
            "========",
            "",
            "host         port  proto  name  state  info",
            "----         ----  -----  ----  -----  ----",
            "192.168.0.2  1025  snmp         open   ",
            "192.168.0.2  1026  snmp         open   "
          ]
        }
      end
    end
  end

  describe "#cmd_vulns" do
    describe "-h" do
      it "should show a help message" do
        db.cmd_vulns "-h"
        expect(@output).to match_array [
          "Print all vulnerabilities in the database",
          "Usage: vulns [addr range]",
          "  -h,--help             Show this help information",
          "  -o <file>             Send output to a file in csv format",
          "  -p,--port <portspec>  List vulns matching this port spec",
          "  -s <svc names>        List vulns matching these service names",
          "  -R,--rhosts           Set RHOSTS from the results of the search",
          "  -S,--search           Search string to filter by",
          "  -i,--info             Display vuln information",
          "Examples:",
          "  vulns -p 1-65536          # only vulns with associated services",
          "  vulns -p 1-65536 -s http  # identified as http on any port"
        ]
      end
    end

  end

  describe "#cmd_workspace" do
    before(:example) do
      db.cmd_workspace "-D"
      @output = []
    end

    describe "<no arguments>" do
      it "should list default workspace" do
        db.cmd_workspace
        expect(@output).to match_array [
          "%red* default%clr"
        ]
      end

      it "should list all workspaces" do
        db.cmd_workspace("-a", "foo")
        @output = []
        db.cmd_workspace
        expect(@output).to match_array [
          "  default",
          "%red* foo%clr"
        ]
      end
    end

    describe "-v" do
      it "should list default workspace verbosely" do
        db.cmd_workspace("-v")
        expect(@output).to match_array [
          "",
          "Workspaces",
          "==========",
          "current  name     hosts  services  vulns  creds  loots  notes",
          "-------  ----     -----  --------  -----  -----  -----  -----",
          "*        default  0      0         0      0      0      0"
        ]
      end

      it "should list all workspaces verbosely" do
        db.cmd_workspace("-a", "foo")
        @output = []
        db.cmd_workspace("-v")
        expect(@output).to match_array [
          "",
          "Workspaces",
          "==========",
          "current  name     hosts  services  vulns  creds  loots  notes",
          "-------  ----     -----  --------  -----  -----  -----  -----",
          "         default  0      0         0      0      0      0",
          "*        foo      0      0         0      0      0      0"
        ]
      end
    end

    describe "-a" do
      it "should add workspaces" do
        db.cmd_workspace("-a", "foo", "bar", "baf")
        expect(@output).to match_array [
          "Added workspace: foo",
          "Added workspace: bar",
          "Added workspace: baf",
          "Workspace: baf"
        ]
      end
    end

    describe "-d" do
      it "should delete a workspace" do
        db.cmd_workspace("-a", "foo")
        expect(framework.db.find_workspace("foo")).not_to be_nil
        db.cmd_workspace("-d", "foo")
        expect(framework.db.find_workspace("foo")).to be_nil
      end
    end

    describe "-D" do
      it "should delete all workspaces" do
        db.cmd_workspace("-a", "foo")
        expect(framework.db.workspaces.size).to be > 1
        db.cmd_workspace("-D")
        expect(framework.db.workspaces.size).to eq 1
      end
    end

    describe "-h" do
      it "should show a help message" do
        db.cmd_workspace "-h"
        expect(@output).to match_array [
          "Usage:",
          "    workspace                  List workspaces",
          "    workspace -v               List workspaces verbosely",
          "    workspace [name]           Switch workspace",
          "    workspace -a [name] ...    Add workspace(s)",
          "    workspace -d [name] ...    Delete workspace(s)",
          "    workspace -D               Delete all workspaces",
          "    workspace -r <old> <new>   Rename workspace",
          "    workspace -h               Show this help information"
        ]
      end
    end
  end
end
