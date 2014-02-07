##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Psexec
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::Client
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  def initialize
    super(
      'Name'        => 'SMB/NFS Share Spidering Utility',
      'Description' => %Q{This module spiders SMB/NFS shares
    and can be extremely useful for identifying sensitive files
    in shares.
      },
      'Author'      =>
        [
          'Alton Johnson @altonjx <alton.jx[at]gmail.com>',
        ],
      'License'     => MSF_LICENSE,
    'References'  => [
      ['URL','https://github.com/altjx/ipwn/blob/master/smb_spider.md']
    ]
    )

    register_options([
    OptString.new('SMBShare', [false, 'The name of a writeable share on the server', 'profile']),
    OptString.new('SMBUser', [true, 'The username to authenticate as']),
    OptString.new('SMBPass', [true, 'The password for the specified user']),
    OptString.new('MaxDepth', [false, 'Max subdirectories to spider', 999]), #thanks Royce Davis for suggestion
    OptString.new('RootDir', [false, 'Root directory within share to spider','/']),
    OptString.new('Verbose', [false, 'Display verbose information', true]),
    OptString.new('ShareFile', [false, 'Import list of \\\\IP\\Share formatted lines']),
    OptString.new('LogResults', [false, 'Outputs spider results to smbspider/ip_share.txt.', false])
    ], self.class)

  end

  def run_host(ip)
    @root_dir = datastore['RootDir']
    @share = datastore['SMBShare']
    @profile_dirs = []
    @users = [] #going to build a list of users if user specifies SMBShare = profile
    @sub_dirs = []
    @ip = ip
    @true_share = ""
    if connect
      begin
        smb_login
      rescue Rex::Proto::SMB::Exceptions::Error => autherror
        print_error("#{@ip} - #{autherror}")
      end
    end
    begin
      if datastore['ShareFile']
         spider_list_of_shares
      elsif @share.downcase.include?("profile")
         spider_profile
      elsif @share.length > 0
         spider_share
    else
       print_error("#{@ip} - No share or input file provided.")
    end
    rescue Rex::Proto::SMB::Exceptions::Error => e
      unless "#{e}".include? "responded with error"
        print_error("#{@ip} - #{@ip}: #{e}")
      end
    end
  end

  def db_note()
    report_note(
      :host => @ip,
      :name => 'smb',
      :port => 445,
      :proto => 'tcp',
      :type => 'smb.spider',
      :data => "Spidering system: #{@ip}\\#{@share}",
      :update => :unique_data
    )
  end

  def spider_list_of_shares()
    print_status("Attempting to spider shares from: #{@ip}")
    list_of_shares = []
    if File.exists? datastore['ShareFile']
      shares = ::File.open(datastore['ShareFile'], 'rb').read.split("\n")
      shares.each do |share|
        if share.include? @ip
          share = share.tr(@ip, '').gsub("\\","").gsub("/","")
          list_of_shares.push(share)
        end
      end
      list_of_shares.each do |unique_share|
        @share = unique_share
        self.simple.connect("\\\\#{@ip}\\#{unique_share}")
        start_spider
        db_note
        while @sub_dirs.length != 0
          start_spider(@sub_dirs[0])
          @sub_dirs.shift
        end
      end
    else
      print_error("File specified in ShareFile doesn't exist. Try unsetting option if it's not being used.")
    end
  end

  def spider_share()
     @true_share = @share
     print_status("Attempting to spider target share: \\\\#{@ip}\\#{@share}")
     self.simple.connect("\\\\#{@ip}\\#{@share}")

     #clean rootdir to avoid issues complying with user preferences
     if @root_dir.length == 1
       if @root_dir == "." or @root_dir == "\\" or @root_dir == "/"
         @root_dir = ""
       end
     end
     if @root_dir.length >= 1
       if @root_dir[0] != "\\"
         @root_dir = "\\#{@root_dir}"
       end
       if @root_dir[-1] == "\\"
         @root_dir = @root_dir[0..-2]
       end
     end

     db_note
     start_spider(@root_dir)
     while @sub_dirs.length != 0
       begin
         start_spider(@sub_dirs[0])
         @sub_dirs.shift
       rescue Rex::Proto::SMB::Exceptions::Error => e
         unless e.to_s.include? "STATUS_OBJECT_PATH_NOT_FOUND"
           print_error("#{e}")
         end
         @sub_dirs.shift
         next
       end
     end
     print_status("Completed spidering target share: \\\\#{@ip}\\#{@share}")
  end

  def spider_profile()
     db_note
     @true_share = "profile"
     print_status("Attempting to spider target: \\\\#{@ip}\\<user profiles>")
     @share = "C$"
     self.simple.connect("\\\\#{@ip}\\#{@share}")
     listing = self.simple.client.find_first("\\*")

     if listing.include?("Documents and Settings")
       userdir = "Documents and Settings"
       @profile_dirs= ["Documents","My Documents","Desktop"] #default dirs for < Vista
     else
       userdir = "Users"
       @profile_dirs = ["Documents","Desktop","Music",
       "Videos","Downloads","Pictures"] #default dirs for => Vista
     end

     #parse out usernames from directory, and add to users array
     listing = self.simple.client.find_first("\\#{userdir}\\*")
     listing.shift; listing.shift #remove "." and ".." from directory listing
     listing.each do |username,trash|
       @users.push(username)
     end

     #spider user profiles
     @users.each do |user|
       @profile_dirs.each do |profile| #go through each profile dir for each user

         #to avoid quitting entire loop on nonexistent profile path, begin/rescue exists here
         begin
            @root_dir = "\\#{userdir}\\#{user}\\#{profile}"
            start_spider("\\#{userdir}\\#{user}\\#{profile}")
         rescue Rex::Proto::SMB::Exceptions::Error => e
           unless e.to_s.include? "STATUS_OBJECT_NAME_NOT_FOUND"
             print_error("#{@ip} - #{e}")
           end
           next
         end

         while @sub_dirs.length != 0
           start_spider(@sub_dirs[0])
           @sub_dirs.shift
         end
       end
     end
     print_status("Completed spidering target: \\\\#{@ip}\\<user profiles>")
  end

  def output(data)
    vprint_status(data)
    if datastore['LogResults'].to_s.downcase != "false"
      unless File.directory?("smbspider")
        Dir.mkdir("smbspider")
      end
      file = ::File.open("smbspider/smbspider_#{@ip}_#{@true_share}.txt", 'ab')
      file.write(data + "\n")
      file.close()
    end
  end

  def start_spider(base_dir="")
    listing = self.simple.client.find_first(base_dir + "\\*")
    listing.shift; listing.shift

    listing.each_pair do |key,val|
      dirslash = ""
      if val['type'] == "D"
        dirslash = "\\"
        dir = "#{@share}#{base_dir}"
        unless dir.scan(/\\/).count-@root_dir.scan(/\\/).count >= datastore['MaxDepth'].to_i
          @sub_dirs.push("#{base_dir}\\#{key}")
        end
     else #we only care about directories with files in them
      output("\\\\#{@ip}\\#{@share}#{base_dir}\\#{key}#{dirslash}".sub("\\\\\\","\\\\"))
      end
    end
  end
end
