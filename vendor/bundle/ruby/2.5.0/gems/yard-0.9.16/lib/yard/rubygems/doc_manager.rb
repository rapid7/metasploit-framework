# frozen_string_literal: true
begin
  require 'rubygems/user_interaction'
  require 'rubygems/doc_manager'
rescue LoadError
  nil # noop
end

class Gem::DocManager
  def self.load_yardoc
    require File.expand_path(File.join(File.dirname(__FILE__), *%w(.. .. yard)))
  end

  def run_yardoc(*args)
    args << '--quiet'
    args << '--backtrace' if Gem.configuration.backtrace
    unless File.file?(File.join(@spec.full_gem_path, '.yardopts'))
      args << @spec.require_paths
      unless @spec.extra_rdoc_files.empty?
        args << '-'
        args += @spec.extra_rdoc_files
      end
    end
    args = args.flatten.map(&:to_s)

    old_pwd = Dir.pwd
    Dir.chdir(@spec.full_gem_path)
    YARD::CLI::Yardoc.run(*args)
  rescue Errno::EACCES => e
    dirname = File.dirname e.message.split("-")[1].strip
    raise Gem::FilePermissionError, dirname
  rescue => ex
    alert_error "While generating documentation for #{@spec.full_name}"
    ui.errs.puts "... MESSAGE:   #{ex}"
    ui.errs.puts "... YARDOC args: #{args.join(' ')}"
    ui.errs.puts "\t#{ex.backtrace.join("\n\t")}" if Gem.configuration.backtrace
    ui.errs.puts "(continuing with the rest of the installation)"
  ensure
    Dir.chdir(old_pwd)
  end

  begin undef setup_rdoc; rescue NameError; nil end
  def setup_rdoc
    if File.exist?(@doc_dir) && !File.writable?(@doc_dir)
      raise Gem::FilePermissionError, @doc_dir
    end

    FileUtils.mkdir_p @doc_dir unless File.exist?(@doc_dir)

    self.class.load_rdoc if @spec.has_rdoc?
    self.class.load_yardoc if @spec.has_yardoc?
  end

  def install_yardoc
    rdoc_dir = File.join(@doc_dir, 'rdoc')

    FileUtils.rm_rf rdoc_dir

    say "Installing YARD documentation for #{@spec.full_name}..."
    run_yardoc '-o', rdoc_dir
  end

  def install_ri_yard
    install_ri_yard_orig if @spec.has_rdoc?
    return if @spec.has_rdoc? == false
    return if @spec.has_yardoc?

    self.class.load_yardoc
    say "Building YARD (yri) index for #{@spec.full_name}..."
    run_yardoc '-c', '-n'
  end

  begin
    alias install_ri_yard_orig install_ri
    alias install_ri install_ri_yard
  rescue NameError; nil end

  def install_rdoc_yard
    if @spec.has_rdoc?
      install_rdoc_yard_orig
    elsif @spec.has_yardoc?
      install_yardoc
    end
  end

  begin
    alias install_rdoc_yard_orig install_rdoc
    alias install_rdoc install_rdoc_yard
  rescue NameError; nil end
end
