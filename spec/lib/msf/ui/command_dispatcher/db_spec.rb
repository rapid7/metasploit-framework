require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/db'

describe Msf::Ui::Console::CommandDispatcher::Db do
  include_context 'Msf::DBManager'
  include_context 'Msf::Ui::Console::Driver'

  subject(:db) do
    described_class.new(msf_ui_console_driver)
  end

  before(:each) do
    # skip seeding because it takes a long time and the seeds aren't needed
    db_manager.stub(:seed)
  end

  describe "#cmd_creds" do
    subject(:cmd_creds) do
      db.cmd_creds(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_creds
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should show usage with address range' do
        output.should include "Usage: creds [addr range]"
      end

      it 'should show usage with options' do
        output.should include "Usage: creds -a <addr range> -p <port> -t <type> -u <user> -P <pass>"
      end

      it 'should show add option' do
        output.should match /-a,--add\s+Add creds to the given addresses instead of listing/
      end

      it 'should show delete option' do
        output.should match /-d,--delete\s+Delete the creds instead of searching/
      end

      it 'should show help option' do
        output.should match /-h,--help\s+Show this help information/
      end

      it 'should show output option' do
        output.should match /-o <file>\s+Send output to a file in csv format/
      end

      it 'should show port option' do
        output.should match /-p,--port <portspec>\s+List creds matching this port spec/
      end

      it 'should show service option' do
        output.should match /-s <svc names>\s+List creds matching these service names/
      end

      it 'should show type option' do
        output.should match /-t,--type <type>\s+Add a cred of this type \(only with -a\)\. Default: password/
      end

      it 'should show user option' do
        output.should match /-u,--user\s+Add a cred for this user \(only with -a\)\. Default: blank/
      end

      it 'should show password option' do
        output.should match /-P,--password\s+Add a cred with this password \(only with -a\)\. Default: blank/
      end

      it 'should show rhost option' do
        output.should match /-R,--rhosts\s+Set RHOSTS from the results of the search/
      end

      it 'should show search option' do
        output.should match /-S,--search\s+Search string to filter by/
      end

      context 'examples' do
        it 'should show default' do
          output.should match /creds\s+# Default, returns all active credentials/
        end

        it 'should show all' do
          output.should match /creds all\s+# Returns all credentials active or not/
        end

        it 'should show namp host' do
          output.should match /creds 1\.2\.3\.4\/24\s+# nmap host specification/
        end

        it 'should show nmap port' do
          output.should match /creds -p 22-25,445\s+# nmap port specification/
        end

        it 'should show combination of arguments and options' do
          output.should include "creds 10.1.*.* -s ssh,smb all"
        end
      end
    end
  end

  describe "#cmd_db_export" do
    subject(:cmd_db_export) do
      db.cmd_db_export(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_db_export
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should include format information' do
        output.should match /db_export -f <format> \[-a\] \[filename\]\s+Format can be one of: xml, pwdump/m
      end
    end
  end

  describe "#cmd_db_import" do
    subject(:cmd_db_import) do
      db.cmd_db_import(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_db_import
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should include usage' do
        output.should include "Usage: db_import <filename> [file2...]"
      end

      it 'should explain file name globbing' do
        output.should include "Filenames can be globs like *.xml, or **/*.xml which will search recursively"
      end

      context 'supported file types' do
        subject(:supported_file_types) do
          match = output.match /Currently supported file types.*/m

          match[0]
        end

        it { should include 'Acunetix XML' }
        it { should include 'Amap Log' }
        it { should include 'Amap Log -m' }
        it { should include 'Appscan XML' }
        it { should include 'Burp Session XML' }
        it { should include 'Foundstone XML' }
        it { should include 'IP360 ASPL' }
        it { should include 'IP360 XML v3' }
        it { should include 'Microsoft Baseline Security Analyzer' }
        it { should include 'Nessus NBE' }
        it { should include 'Nessus XML (v1 and v2)' }
        it { should include 'NetSparker XML' }
        it { should include 'NeXpose Simple XML' }
        it { should include 'NeXpose XML Report' }
        it { should include 'Nmap XML' }
        it { should include 'OpenVAS Report' }
        it { should include 'Qualys Asset XML' }
        it { should include 'Qualys Scan XML' }
        it { should include 'Retina XML' }
      end
    end
  end

  describe "#cmd_hosts" do
    subject(:cmd_hosts) do
      db.cmd_hosts(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_hosts
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should include usage' do
        output.should include 'Usage: hosts [ options ] [addr1 addr2 ...]'
      end

      it 'should include add option' do
        output.should match /-a,--add\s+Add the hosts instead of searching/
      end

      it 'should include delete option' do
        output.should match /-d,--delete\s+Delete the hosts instead of searching/
      end

      it 'should include columns option' do
        output.should match /-c <col1,col2>\s+Only show the given columns \(see list below\)/
      end

      it 'should include help option' do
        output.should match /-h,--help\s+Show this help information/
      end

      it 'should include up option' do
        output.should match /-u,--up\s+Only show hosts which are up/
      end

      it 'should include output option' do
        output.should match /-o <file>\s+Send output to a file in csv format/
      end

      it 'should include rhosts option' do
        output.should match /-R,--rhosts\s+Set RHOSTS from the results of the search/
      end

      it 'should include search option' do
        output.should match /-S,--search\s+Search string to filter by/
      end

      it 'should include available columns' do
        output.should include "Available columns: address, comm, comments, created_at, cred_count, exploit_attempt_count, host_detail_count, info, mac, name, note_count, os_flavor, os_lang, os_name, os_sp, purpose, scope, service_count, state, updated_at, virtual_host, vuln_count"
      end
    end
  end

  describe "#cmd_loot" do
    subject(:cmd_loot) do
      db.cmd_loot(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_loot
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should show generic usage' do
        output.should include 'Usage: loot <options>'
      end

      it 'should show info usage' do
        output.should include "Info: loot [-h] [addr1 addr2 ...] [-t <type1,type2>]"
      end

      it 'should show add usage' do
        output.should include "Add: loot -f [fname] -i [info] -a [addr1 addr2 ...] [-t [type]"
      end

      it 'should show delete usage' do
        output.should include "Del: loot -d [addr1 addr2 ...]"
      end

      it 'should show add option' do
        output.should match /-a,--add\s+Add loot to the list of addresses, instead of listing/
      end

      it 'should show delete option' do
        output.should match /-d,--delete\s+Delete \*all\* loot matching host and type/
      end

      it 'should show file option' do
        output.should match /-f,--file\s+File with contents of the loot to add/
      end

      it 'should show info option' do
        output.should match /-i,--info\s+Info of the loot to add/
      end

      it 'should show type option' do
        output.should match /-t <type1,type2>\s+Search for a list of types/
      end

      it 'should show help option' do
        output.should match /-h,--help\s+Show this help information/
      end

      it 'should show search option' do
        output.should match /-S,--search\s+Search string to filter by/
      end
    end
  end

  describe "#cmd_notes" do
    subject(:cmd_notes) do
      db.cmd_notes(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_notes
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should show usage' do
        output.should include "Usage: notes [-h] [-t <type1,type2>] [-n <data string>] [-a] [addr range]"
      end

      it 'should show add option' do
        output.should match /-a,--add\s+Add a note to the list of addresses, instead of listing/
      end

      it 'should show delete option' do
        output.should match /-d,--delete\s+Delete the hosts instead of searching/
      end

      it 'should show note option' do
        output.should match /-n,--note <data>\s+Set the data for a new note \(only with -a\)/
      end

      it 'should show type option' do
        output.should match /-t <type1,type2>\s+Search for a list of types/
      end

      it 'should show help option' do
        output.should match /-h,--help\s+Show this help information/
      end

      it 'should show rhosts option' do
        output.should match /-R,--rhosts\s+Set RHOSTS from the results of the search/
      end

      it 'should show search option' do
        output.should match /-S,--search\s+Regular expression to match for search/
      end

      it 'should show sort option' do
        output.should match /--sort <field1,field2>\s+Fields to sort by \(case sensitive\)/
      end
    end
  end

  describe "#cmd_services" do
    subject(:cmd_services) do
      db.cmd_services(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_services
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should show usage' do
        output.should include "Usage: services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <filename>] [addr1 addr2 ...]"
      end

      it 'should show add option' do
        output.should match /-a,--add\s+Add the services instead of searching/
      end

      it 'should show delete option' do
        output.should match /-d,--delete\s+Delete the services instead of searching/
      end

      it 'should show columns option' do
        output.should match /-c <col1,col2>\s+Only show the given columns/
      end

      it 'should show help option' do
        output.should match /-h,--help\s+Show this help information/
      end

      it 'should show service option' do
        output.should match /-s <name1,name2>\s+Search for a list of service names/
      end

      it 'should show port option' do
        output.should match /-p <port1,port2>\s+Search for a list of ports/
      end

      it 'should show protocol option' do
        output.should match /-r <protocol>\s+Only show \[tcp\|udp\] services/
      end

      it 'should show up option' do
        output.should match /-u,--up\s+Only show services which are up/
      end

      it 'should show output option' do
        output.should match /-o <file>\s+Send output to a file in csv format/
      end

      it 'should show rhost option' do
        output.should match /-R,--rhosts\s+Set RHOSTS from the results of the search/
      end

      it 'should show search option' do
        output.should match /-S,--search\s+Search string to filter by/
      end

      it 'should show available columns' do
        output.should include "Available columns: created_at, info, name, port, proto, state, updated_at"
      end
    end

    context 'with services' do
      let(:address) do
        '192.168.0.1'
      end

      let(:host) do
        FactoryGirl.create(
            :mdm_host,
            address: address,
            workspace: framework.db.workspace
        )
      end

      let(:ports) do
        [
            1024,
            1025,
            1026
        ]
      end

      before(:each) do
        ports.each do |port|
          FactoryGirl.create(
              :mdm_service,
              host: host,
              port: port
          )
        end
      end

      describe "-p" do

        let(:arguments) do
          ['-p', "#{ports[0]},#{ports[1]}"]
        end

        it 'should not include service with non-matching port' do
          output.should_not include ports[-1].to_s
        end

        it 'should include services with matching ports' do
          output.should include ports[0].to_s
          output.should include ports[1].to_s
        end
      end

      describe "-np", pending: 'Redmine 4841' do
        let(:arguments) do
          ['-np', ports[0].to_s]
        end

        it 'should not include excluded port' do
          output.should_not include ports[0].to_s
        end

        it 'should include non-excluded ports' do
          output.should include ports[1].to_s
          output.should include ports[2].to_s
        end
      end
    end
  end

  describe "#cmd_vulns" do
    subject(:cmd_vulns) do
      db.cmd_vulns(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_vulns
      }
    end

    describe "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should include description' do
        output.should include "Print all vulnerabilities in the database"
      end

      it 'should include usage' do
        output.should include "Usage: vulns [addr range]"
      end

      it 'should include help option' do
        output.should match /-h,--help\s+Show this help information/
      end

      it 'should include port option' do
        output.should match /-p,--port <portspec>\s+List vulns matching this port spec/
      end

      it 'should include service option' do
        output.should match /-s <svc names>\s+List vulns matching these service names/
      end

      it 'should include search option' do
        output.should match /-S,--search\s+Search string to filter by/
      end

      it 'should include info option' do
        output.should match /-i,--info\s+Display Vuln Info/
      end
    end
  end

  context "#cmd_workspace" do
    subject(:cmd_workspace) do
      db.cmd_workspace(*arguments)
    end

    let(:output) do
      capture(:stdout) {
        cmd_workspace
      }
    end

    context "-h" do
      let(:arguments) do
        ['-h']
      end

      it 'should show how to list workspaces' do
        output.should match /workspace\s+List workspaces/
      end

      it 'should show how to switch workspaces' do
        output.should match /workspace \[name\]\s+Switch workspace/
      end

      it 'should show how to add workspace(s)' do
        output.should match /workspace -a \[name\] \.\.\.\s+Add workspace\(s\)/
      end

      it 'should show how to delete workspace(s)' do
        output.should match /workspace -d \[name\] \.\.\.\s+Delete workspace\(s\)/
      end

      it 'should show how to get help' do
        output.should match /workspace -h\s+Show this help information/
      end

      it 'should show how to rename a workspace' do
        output.should match /workspace -r <old> <new>\s+Rename workspace/
      end
    end
  end

  describe "#db_nmap" do
    it "should have some specs describing its output"
  end

  describe "#db_rebuild_cache" do
    it "should have some specs describing its output"
  end
end
