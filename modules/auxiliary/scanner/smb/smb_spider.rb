# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB::Psexec
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  SIMPLE = Rex::Proto::SMB::Client
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  def initialize (info = {})
    super(update_info(info,
      'Name'        => 'SMB/NFS Share Spidering Utility',
      'Description' => %q{This module spiders SMB/NFS shares
    and can be extremely useful for identifying sensitive files
    in shares.
      },
      'Author'      =>
        [
          'Alton Johnson <alton.jx[at]gmail.com>',
        ],
      'License'     => MSF_LICENSE,
      'References'   => [
         ['URL','https://github.com/altjx/ipwn/blob/master/smb_spider.md']
      ]
    ))

    register_options([
    OptString.new('SMBShare', [false, 'The name of a readable share on the server', '<profiles>']),
    OptString.new('SMBUser', [false, 'The username to authenticate as']),
    OptString.new('SMBPass', [false, 'The password for the specified user']),
    OptInt.new('MaxDepth', [false, 'Max subdirectories to spider', 999]), # thanks Royce Davis for suggestion
    OptString.new('RootDir', [false, 'Root directory within share to spider','/']),
    OptPath.new('ShareFile', [false, 'Import list of \\\\IP\\Share formatted lines']),
    OptString.new('Verbose', [true, 'Display verbose information', true]),
    OptString.new('LogResults', [false, 'Outputs spider results to smbspider/ip_share.txt.', false])
    ], self.class)

  end

  def run_host(ip)
    @root_dir = datastore['RootDir']
    @sub_dirs = []
    @true_share = ""
    if connect
      begin
        smb_login
      rescue Rex::Proto::SMB::Exceptions::Error => autherror
        print_error("#{ip} - #{autherror}")
      end
    end
    begin
      if datastore['ShareFile'].to_s.length != 0
         spider_list_of_shares(ip)
      elsif datastore['SMBShare'].downcase == "<profiles>"
         spider_profile(ip)
      elsif datastore['SMBShare'].length > 0
         spider_share(ip, datastore['SMBShare'])
      else
         print_error("#{ip} - No share or input file provided.")
    end
    rescue Rex::Proto::SMB::Exceptions::Error => e
      unless "#{e}".include? "responded with error"
        print_error("#{ip} - #{ip}: #{e}")
      end
    end
  end

  def db_note(ip, share)
    report_note(
      :host => ip,
      :name => 'smb',
      :port => 445,
      :proto => 'tcp',
      :type => 'smb.spider',
      :data => "Spidering system: #{ip}\\#{share}",
      :update => :unique_data
    )
  end

  def spider_list_of_shares(ip)
    print_status("Attempting to spider shares from: #{ip}")
    list_of_shares = []
    if File.exists? datastore['ShareFile']
      shares = ::File.open(datastore['ShareFile'], 'rb').read.split("\n")
      shares.each do |share|
        if share.include? ip
          share = share.tr(ip, '').gsub("\\","").gsub("/","")
          list_of_shares.push(share)
        end
      end
      list_of_shares.each do |unique_share|
        self.simple.connect("\\\\#{ip}\\#{unique_share}")
            @true_share = unique_share
        start_spider("", ip, unique_share)
        db_note(ip, unique_share)
        while @sub_dirs.length != 0
          start_spider(@sub_dirs[0], ip, unique_share)
          @sub_dirs.shift
        end
      end
    else
      print_error("File specified in ShareFile doesn't exist.")
    end
  end

  def spider_share(ip, share)
     @true_share = share
     print_status("Attempting to spider target share: \\\\#{ip}\\#{share}")
     self.simple.connect("\\\\#{ip}\\#{share}")

     # clean rootdir to avoid issues complying with user preferences
     if @root_dir == "." or @root_dir == "\\" or @root_dir == "/"
       @root_dir = ""
     end
     if @root_dir.length >= 1
       if @root_dir[0] != "\\"
         @root_dir = "\\#{@root_dir}"
       end
       @root_dir.chomp!("\\")
     end

     db_note(ip, share)
     start_spider(@root_dir, ip, share)
     while @sub_dirs.length != 0
       begin
         start_spider(@sub_dirs[0], ip, share)
         @sub_dirs.shift
       rescue Rex::Proto::SMB::Exceptions::Error => e
         unless e.to_s.include? "STATUS_OBJECT_PATH_NOT_FOUND"
           print_error("#{e}")
         end
         @sub_dirs.shift
         next
       end
     end
     print_status("Completed spidering target share: \\\\#{ip}\\#{share}")
  end

  def spider_profile(ip)
     users = []
     profile_dirs = []
     db_note(ip, "profiles")
     @true_share = "profile"
     print_status("Attempting to spider target: \\\\#{ip}\\<user profiles>")
     self.simple.connect("\\\\#{ip}\\C$")
     listing = self.simple.client.find_first("\\*")

     if listing.include?("Documents and Settings")
       userdir = "Documents and Settings"
       profile_dirs= ["Documents","My Documents","Desktop"] # default dirs for < Vista
     else
       userdir = "Users"
       profile_dirs = ["Documents","Desktop","Music",
       "Videos","Downloads","Pictures"] # default dirs for => Vista
     end

     # parse out usernames from directory, and add to users array
     listing = self.simple.client.find_first("\\#{userdir}\\*")
     listing.shift; listing.shift # remove "." and ".." from directory listing
     listing.each do |username,trash|
       users.push(username)
     end

     # spider user profiles
     users.each do |user|
       profile_dirs.each do |profile| # go through each profile dir for each user

         # to avoid quitting entire loop on nonexistent profile path, begin/rescue exists here
         begin
            @root_dir = "\\#{userdir}\\#{user}\\#{profile}"
            start_spider("\\#{userdir}\\#{user}\\#{profile}", ip, "C$")
         rescue Rex::Proto::SMB::Exceptions::Error => e
           unless e.to_s.include? "STATUS_OBJECT_NAME_NOT_FOUND"
             print_error("#{ip} - #{e}")
           end
           next
         end

         while @sub_dirs.length != 0
           start_spider(@sub_dirs[0], ip, "C$")
           @sub_dirs.shift
         end
       end
     end
     print_status("Completed spidering target: \\\\#{ip}\\<user profiles>")
  end

  def output(data, ip)
    vprint_good(data)
    if datastore['LogResults'].to_s.downcase != "false"
      unless File.directory?("smbspider")
        Dir.mkdir("smbspider")
      end
      file = ::File.open("smbspider/smbspider_#{ip}_#{@true_share}.txt", 'ab')
      file.write(data + "\n")
      file.close()
    end
  end

  def start_spider(base_dir="", ip, share)
    listing = self.simple.client.find_first(base_dir + "\\*")
    listing.shift; listing.shift

    listing.each_pair do |key,val|
      dirslash = ""
      if val['type'] == "D"
        dirslash = "\\"
        dir = "#{share}#{base_dir}"
        unless dir.scan(/\\/).count-@root_dir.scan(/\\/).count >= datastore['MaxDepth'].to_i
          @sub_dirs.push("#{base_dir}\\#{key}")
        end
      end
      output("\\\\#{ip}\\#{share}#{base_dir}\\#{key}#{dirslash}".sub("\\\\\\","\\\\"), ip)
    end
  end
end
