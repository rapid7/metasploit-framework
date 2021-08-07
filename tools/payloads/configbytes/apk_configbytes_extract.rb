#!/usr/bin/env ruby
# -*- coding: binary -*-

class ExtractError < StandardError; end
class HelpError < StandardError; end
class UsageError < ExtractError; end

require 'rex'
require 'tmpdir'
require 'optparse'
require 'open3'
require 'nokogiri'
require 'fileutils'

def run_cmd(args, verbose)
  begin
    if verbose
      $stdout.puts "[+] Running: #{args.join(" ")}"
    end
    
    stdin, stdout, stderr = Open3.popen3(*args)
    $stdout.puts stdout.read + stderr.read if verbose
    return stdout.read + stderr.read
  rescue Errno::ENOENT
    return nil
  end
end

def parse_manifest(manifest_file)
  File.open(manifest_file, "rb"){|file|
    data = File.read(file)
    return Nokogiri::XML(data)
  }
end

def extract_data(java_file, text_file)
  file_data = File.read(java_file)
  mid = file_data.split("[]{")
  bytes = mid[1].split("}")
  bytes[0]

  File.open(text_file, 'wb') do |f|
    f.write(bytes[0])
  end

  $stdout.puts "[+] Saved as: #{text_file}"
end

def check_tools(verbose)
  # CHECK IF ALL TOOLS ARE INCLUDED BEFORE STARTING
  tools = ["unzip", "d2j-dex2jar", "java", "apktool"]

  tools.each do |tool|
    path = Rex::FileUtils.find_full_path(tool)
    if path && ::File.file?(path)
      $stdout.puts "[+] Tool present: #{path}" if verbose
    else
      raise RuntimeError, "[-] #{tool} command not found."
    end
  end
end

def parse_args(args)
  opts = {}
  opt = OptionParser.new
  banner = "apk_configbytes_extract - a tool to extract configbytes from an android payload.\n"
  banner << "Usage: #{$0} < -a apk-file -o path -j path > [options]\n"
  banner << "Example: #{$0} -a metasploit.apk -o /root/configbytes.txt -j /root/fernflower.jar"
  opt.banner = banner
  opt.separator('')
  opt.separator('Options:')

  opt.on('-a', '--apk             <path>', String, 'Specify apk to extract configbytes') do |a|
    opts[:apk] = a
  end

  opt.on('-o', '--out             <path>', String, 'Save configbytes to a file') do |o|
    opts[:out] = o
  end

  opt.on('-j', '--jar             <path>', String, 'Specify fernflower path') do |j|
    opts[:jar] = j
  end

  opt.on('-v', '--verbose', 'Displays verbose output') do
    opts[:verbose] = true
  end

  opt.on('-k', '--keep', 'Keep working directory') do
    opts[:keep] = true
  end

  opt.on_tail('-h', '--help', 'Show this message') do
    raise HelpError, "#{opt}"
  end

  begin
    opt.parse!(args)
  rescue OptionParser::InvalidOption => e
    raise UsageError, "Invalid option\n#{opt}"
  rescue OptionParser::MissingArgument => e
    raise UsageError, "Missing required argument for option\n#{opt}"
  end

  if opts.empty?
    raise UsageError, "No options\n#{opt}"
  end

  if opts[:apk].nil?
    raise UsageError, "Missing required argument apk file\n#{opt}"
    exit(1)
  end

  if opts[:jar].nil?
    raise UsageError, "Missing required argument fernflower path\n#{opt}"
    exit(1)
  end

  opts
end

begin
  options = parse_args(ARGV)
rescue HelpError => e
  $stderr.puts e.message
  exit(1)
rescue ExtractError => e
  $stderr.puts "Error: #{e.message}"
  exit(1)
end

begin
  verbose = options[:verbose]

  check_tools(verbose)

  temp_dir = Dir.mktmpdir
  temp_dir << "/"

  if options[:out].nil?
    $stdout.puts "[-] No output option selected, working in #{temp_dir}"
    output = "#{temp_dir}configbytes.txt"
    options[:keep] = true
  else
    output = options[:out]
  end

  apk = options[:apk]
  zip_file = "#{temp_dir}temp.zip"
  temp_apk = "#{temp_dir}temp.apk"
  FileUtils.cp(apk, temp_apk)

  $stdout.puts "[+] Renaming apk file to zip file"
  File.rename(temp_apk, zip_file)

  $stdout.puts "[+] Using unzip on zip file for dex file"
  run_cmd(["unzip", zip_file, "-d", temp_dir], verbose)

  $stdout.puts "[+] Using d2j-dex2jar on dex file to create jar file"
  dex_file = "#{temp_dir}classes.dex"
  jar_file = "#{temp_dir}classes.jar"
  run_cmd(["d2j-dex2jar", "-o", jar_file, dex_file], verbose)

  $stdout.puts "[+] Using unzip on jar file for class files"
  classes_dir = "#{temp_dir}classes/"
  FileUtils.mkdir_p classes_dir
  run_cmd(["unzip", jar_file, "-d", classes_dir], verbose)

  $stdout.puts "[+] Using apktool to read AndroidManifest"
  decompile_dir = "#{temp_dir}decompile/"
  run_cmd(["apktool", "d", apk, "-o", decompile_dir], verbose)

  amanifest = parse_manifest("#{decompile_dir}AndroidManifest.xml")
  package_path = amanifest.xpath("//manifest").first['package'].gsub(/\./, "/")
  $stdout.puts "[+] Package path found: #{package_path}"

  # DEFAULT METERPRETER PAYLOAD
  default_payload_file = "#{classes_dir}#{package_path}/Payload.class"

  # CREATING SEARCHABLE PAYLOAD
  class_file = File.join("#{classes_dir}#{package_path}/?????", "?????.class")
  class_files = Dir.glob(class_file)
  searchable_payload = class_files[0]

  # SETTING UP JAVA DECOMPILER
  java_dir = "#{temp_dir}java/"
  FileUtils.mkdir_p java_dir
  fernflower_jar = options[:jar]

  if File.exist?(default_payload_file) # SEARCH DEFAULT METASPLOIT APK
    $stdout.puts "[+] Using fernflower to change class file to java file"
    run_cmd(["java", "-jar", fernflower_jar, default_payload_file, java_dir], verbose)

    default_payload_file = File.dirname(default_payload_file)
    $stdout.puts "[+] Class Path: #{default_payload_file}"

    java_file ="#{java_dir}Payload.java"
    $stdout.puts "[+] Metasploit Payload Class found!\n[+] #{java_file}"
    extract_data(java_file, output)

  elsif !searchable_payload.nil? # SEARCHING APK WTIH METERPRETER INJECTION
    $stdout.puts "[+] Looking for Backdoored Metasploit Payload Classes"
    $stdout.puts "[+] Using fernflower to change class files to java files"
    for class_file in class_files
      run_cmd(["java", "-jar", fernflower_jar, class_file, java_dir], verbose)
    end

    class_path = File.dirname(class_file)
    $stdout.puts "[+] Class Path: #{class_path}"

    java_file = File.join("#{java_dir}", "?????.java")
    java_files = Dir.glob(java_file)

    for java_file in java_files
      if File.read("#{java_file}").include? "byte"
        $stdout.puts "[+] Metasploit Backdoored Payload Class found!\n[+] #{java_file}"
        extract_data(java_file, output)
      end
    end

  else
    unless options[:keep] then FileUtils.rm_rf("#{temp_dir}") end
    raise RuntimeError, "Unable to find payload class."
  end

  unless options[:keep] then FileUtils.remove_entry temp_dir end

rescue ::Exception => e
  $stderr.puts "Error: #{e.class}: #{e.message}\n#{e.backtrace * "\n"}"
end
