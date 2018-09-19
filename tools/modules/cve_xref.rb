#!/usr/bin/env ruby

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))
$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'nokogiri'

module CVE
  class XRefTable

    attr_reader :module_full_name_ref
    attr_reader :edb_ref
    attr_reader :bid_ref
    attr_reader :osvdb_ref
    attr_reader :msb_ref
    attr_reader :zdi_ref
    attr_reader :url_refs

    def initialize(refs)
      @module_full_name_ref = refs['fullname']
      @edb_ref               = refs['EDB']
      @bid_ref               = refs['BID']
      @osvdb_ref             = refs['OSVDB']
      @msb_ref               = refs['MSB']
      @zdi_ref               = refs['ZDI']
      @url_refs              = refs['URL']
    end

    def has_match?(ref_match)
      if (
           (module_full_name_ref && ref_match.match(/#{module_full_name_ref}/)) ||
           (edb_ref               && ref_match.match(/EXPLOIT\-DB:#{edb_ref}$/)) ||
           (osvdb_ref             && ref_match.match(/OSVDB:#{osvdb_ref}$/)) ||
           (bid_ref               && ref_match.match(/BID:#{bid_ref}$/)) ||
           (msb_ref               && ref_match.match(/http:\/\/technet\.microsoft\.com\/security\/bulletin\/#{msb_ref}$/)) ||
           (zdi_ref               && ref_match.match(/zerodayinitiative\.com\/advisories\/ZDI\-#{zdi_ref}/)) ||
           (url_refs_match?(ref_match))
        )
        return true
      end

      false
    end

    private

    def url_refs_match?(ref_match)
      return false unless url_refs
      return false unless ref_match.match(/^http/)

      url_refs.each do |url|
        return true if url == ref_match
      end

      false
    end
  end

  class Database
    attr_reader :database

    def initialize(db_path)
      @database = normalize(db_path)
    end

    def cross_reference(reference_matches)
      return nil if reference_matches.empty?
      xref_table = XRefTable.new(reference_matches)

      database.each_pair do |cve_name, references|
        references.each do |cve_ref|
          if xref_table.has_match?(cve_ref)
            return cve_name
          end
        end
      end

      nil
    end

    private

    def normalize(db_path)
      html = load_cve_html_file(db_path)
      normalize_html_to_hash(html)
    end

    def load_cve_html_file(db_path)
      puts "[*] Loading database..."
      raw_data = File.read(db_path)
      Nokogiri::HTML(raw_data)
    end

    def normalize_html_to_hash(html)
      puts "[*] Normalizing database..."

      db = {}
      current_cve = nil
      metasploit_refs = []
      html.traverse do |element|
        if current_cve
          if element.text =~ /(https*:\/\/.*metasploit.+)/
            metasploit_refs << $1
          elsif element.text =~ /(http:\/\/www\.exploit\-db\.com\/.+)/
            metasploit_refs << $1
          elsif element.text =~ /(BID:\d+)/
            metasploit_refs << $1
          elsif element.text =~ /(OSVDB:\d+)/
            metasploit_refs << $1
          elsif element.text =~ /http:\/\/technet\.microsoft\.com\/security\/bulletin\/(MS\d+\-\d+)$/
            metasploit_refs << $1
          elsif element.text =~ /zerodayinitiative\.com\/advisories\/(ZDI\-\d+\-\d+)/
            metasploit_refs << $1
          elsif element.text =~ /URL:(http.+)/
            metasploit_refs << $1
          end
        end

        if element.text =~ /^Name: (CVE\-\d+\-\d+)$/
          current_cve = $1
        elsif element.text =~ /^Votes:/
          unless metasploit_refs.empty?
            db[current_cve] = metasploit_refs
          end
          current_cve = nil
          metasploit_refs = []
        end
      end

      db
    end
  end

end

class Utility
  def self.ignore_module?(module_full_name)
    [
      'exploit/multi/handler'
    ].include?(module_full_name)
  end

  def self.collect_references_from_module!(module_references, ref_ids, mod)
    if ref_ids.include?('EDB')
      edb_ref = mod.references.select { |r| r.ctx_id == 'EDB' }.first.ctx_val
      module_references['EDB'] = edb_ref
    end

    if ref_ids.include?('BID')
      bid_ref = mod.references.select { |r| r.ctx_id == 'BID' }.first.ctx_val
      module_references['BID'] = bid_ref
    end

    if ref_ids.include?('OSVDB')
      osvdb_ref = mod.references.select { |r| r.ctx_id == 'OSVDB' }.first.ctx_val
      module_references['OSVDB'] = osvdb_ref
    end

    if ref_ids.include?('MSB')
      msb_ref = mod.references.select { |r| r.ctx_id == 'MSB' }.first.ctx_val
      module_references['MSB'] = msb_ref
    end

    if ref_ids.include?('ZDI')
      zdi_ref = mod.references.select { |r| r.ctx_id == 'ZDI' }.first.ctx_val
      module_references['ZDI'] = zdi_ref
    end

    if ref_ids.include?('URL')
      url_refs = mod.references.select { |r| r.ctx_id == 'URL' }.collect { |r| r.ctx_val if r }
      module_references['URL'] = url_refs
    end
  end

end

require 'msfenv'
require 'msf/base'

def main
  filter  = 'All'
  filters = ['all','exploit','payload','post','nop','encoder','auxiliary']
  type    = 'CVE'
  db_path = nil

  opts = Rex::Parser::Arguments.new(
    "-h" => [ false, 'Help menu.' ],
    "-f" => [ true,  'Filter based on Module Type [All,Exploit,Payload,Post,NOP,Encoder,Auxiliary] (Default = ALL).'],
    "-d" => [ true,  'Source of CVE database in HTML (allitems.html)'],
  )

  opts.parse(ARGV) { |opt, idx, val|
    case opt
    when "-h"
      puts "\nMetasploit script for finding CVEs from other references."
      puts "=========================================================="
      puts opts.usage
      exit
    when "-f"
      unless filters.include?(val.downcase)
        puts "Invalid Filter Supplied: #{val}"
        puts "Please use one of these: #{filters.map{|f|f.capitalize}.join(", ")}"
        exit
      end
      filter = val
    when "-d"
      unless File.exists?(val.to_s)
        raise RuntimeError, "#{val} not found"
      end

      db_path = val
    end
  }

  framework_opts = { 'DisableDatabase' => true }
  framework_opts[:module_types] = [ filter.downcase ] if filter.downcase != 'all'
  $framework = Msf::Simple::Framework.create(framework_opts)
  cve_database = CVE::Database.new(db_path)

  puts "[*] Going through Metasploit modules for missing references..."
  $framework.modules.each { |name, mod|
    if mod.nil?
      elog("Unable to load #{name}")
      next
    end

    elog "Loading #{name}"
    m = mod.new
    next if Utility.ignore_module?(m.fullname)

    ref_ids = m.references.collect { |r| r.ctx_id }
    next if ref_ids.include?(type)

    elog "Checking references for #{m.fullname}"
    module_references = {}
    module_references['fullname'] = m.fullname
    Utility.collect_references_from_module!(module_references, ref_ids, m)
    cve_match = cve_database.cross_reference(module_references)
    if cve_match
      puts "[*] #{m.fullname}: Found #{cve_match}"
    end
  }
end

if __FILE__ == $PROGRAM_NAME
  main
end

