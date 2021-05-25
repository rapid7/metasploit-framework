# -*- coding: binary -*-
#
module Msf::Post::FileStat

class Stat
  attr_accessor :stathash

 @@ftypes = [
    'fifo', 'characterSpecial', 'directory',
    'blockSpecial', 'file', 'link', 'socket'
  ]


  def initialize(filename, session)
    data = session.shell_command_token("stat --format='%d,%i,%h,%u,%g,%t,%s,%B,%b,%x,%y,%z,%f' #{filename}").to_s.chomp
    data = data.split(",")
    @stathash = Hash.new
    @stathash['st_dev'] = data[0].to_i
    @stathash['st_ino'] = data[1].to_i
    @stathash['st_nlink'] = data[2].to_i
    @stathash['st_uid'] = data[3].to_i
    @stathash['st_gid'] = data[4].to_i
    @stathash['st_rdev'] = data[5].to_i
    @stathash['st_size'] = data[6].to_i
    @stathash['st_blksize'] = data[7].to_i
    @stathash['st_blocks'] = data[8].to_i
    @stathash['st_atime'] = data[9].to_time
    @stathash['st_mtime'] = data[10].to_time
    @stathash['st_ctime'] = data[11].to_time
    @stathash['st_mode'] = data[12].to_i(16) #stat command returns hex value of mode" 
  end

  def dev
    self.stathash['st_dev']
  end
  def ino
    self.stathash['st_ino']
  end
  def mode
    self.stathash['st_mode']
  end
  def nlink
    self.stathash['st_nlink']
  end
  def uid
    self.stathash['st_uid']
  end
  def gid
    self.stathash['st_gid']
  end
  def rdev
    self.stathash['st_rdev']
  end
  def size
    self.stathash['st_size']
  end
  def blksize
    self.stathash['st_blksize']
  end
  def blocks
    self.stathash['st_blocks']
  end
  def atime
    (self.stathash['st_atime'])
  end
  def mtime
    (self.stathash['st_mtime'])
  end
  def ctime
    (self.stathash['st_ctime'])
  end

  def filetype?(mask)
    return true if mode & 0170000 == mask
    return false
  end

  def blockdev?
    filetype?(060000)
  end
  def chardev?
    filetype?(020000)
  end
  def directory?
    filetype?(040000)
  end
  def file?
    filetype?(0100000)
  end
  def pipe?
    filetype?(010000) 
  end
  def socket?
    filetype?(0140000)
  end
  def symlink?
    filetype?(0120000)
  end

  def ftype
    return @@ftypes[(mode & 0170000) >> 13].dup
  end

  def perm?(mask)
    return true if mode & mask == mask
    return false
  end

  def setgid?
    perm?(02000)
  end
  def setuid?
    perm?(04000)
  end
  def sticky?
    perm?(01000)
  end

  def executable?
    raise NotImplementedError
  end
  def executable_real?
    raise NotImplementedError
  end
  def grpowned?
    raise NotImplementedError
  end
  def owned?
    raise NotImplementedError
  end
  def readable?
    raise NotImplementedError
  end
  def readable_real?
    raise NotImplementedError
  end
  def writeable?
    raise NotImplementedError
  end
  def writeable_real?
    raise NotImplementedError
  end
 
  def prettymode
    m  = mode
    om = '%04o' % m
    perms = ''

    3.times {
      perms = ((m & 01) == 01 ? 'x' : '-') + perms
      perms = ((m & 02) == 02 ? 'w' : '-') + perms
      perms = ((m & 04) == 04 ? 'r' : '-') + perms
      m >>= 3
    }

    return "#{om}/#{perms}"
  end

  def pretty
    "  Size: #{size}   Blocks: #{blocks}   IO Block: #{blksize}   Type: #{rdev}\n"\
    "Device: #{dev}  Inode: #{ino}  Links: #{nlink}\n"\
    "  Mode: #{prettymode}\n"\
    "   Uid: #{uid}  Gid: #{gid}\n"\
    "Access: #{atime}\n"\
    "Modify: #{mtime}\n"\
    "Change: #{ctime}\n"
  end
end
end
