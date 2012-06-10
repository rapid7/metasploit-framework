require 'rubygems'
Gem.load_yaml
require 'rdoc'
require 'gauntlet'
require 'fileutils'

##
# Allows for testing of RDoc against every gem

class RDoc::Gauntlet < Gauntlet

  def initialize # :nodoc:
    super

    @args = nil
    @type = nil
  end

  ##
  # Runs an RDoc generator for gem +name+

  def run name
    return if self.data.key? name

    dir = File.expand_path "~/.gauntlet/data/#{@type}/#{name}"
    FileUtils.rm_rf dir if File.exist? dir

    yaml = File.read 'gemspec'
    begin
      spec = Gem::Specification.from_yaml yaml
    rescue Psych::SyntaxError
      puts "bad spec #{name}"
      self.data[name] = false
      return
    end

    args = @args.dup
    args << '--op' << dir
    args.push(*spec.rdoc_options)
    args << spec.require_paths
    args << spec.extra_rdoc_files
    args = args.flatten.map { |a| a.to_s }
    args.delete '--quiet'

    puts "#{name} - rdoc #{args.join ' '}"

    self.dirty = true
    r = RDoc::RDoc.new

    begin
      r.document args
      self.data[name] = true
      puts 'passed'
      FileUtils.rm_rf dir
    rescue Interrupt, StandardError, RDoc::Error, SystemStackError => e
      puts "failed - (#{e.class}) #{e.message}"
      self.data[name] = false
    end
  rescue Gem::Exception
    puts "bad gem #{name}"
  ensure
    puts
  end

  ##
  # Runs the gauntlet with the given +type+ (rdoc or ri) and +filter+ for
  # which gems to run

  def run_the_gauntlet type = 'rdoc', filter = nil
    @type = type || 'rdoc'
    @args = type == 'rdoc' ? [] : %w[--ri]
    @data_file = "#{DATADIR}/#{@type}-data.yml"

    super filter
  end

end

type = ARGV.shift
filter = ARGV.shift
filter = /#{filter}/ if filter

RDoc::Gauntlet.new.run_the_gauntlet type, filter

