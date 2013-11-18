# -*- coding: binary -*-

require 'rex/post/io'

module Rex
module Post

# make this a module so we can mix it in, and have inheritence like..
# => [Rex::Post::DispatchNinja::File, Rex::Post::File,
# Rex::Post::DispatchNinja::IO, Rex::Post::IO, Object, Kernel]

###
#
# This module simulates the behavior that one would expect from the Ruby File
# class against a remote entity.  Refer to the ruby documentation for expected
# behavior.
#
###
module File

  protected
    # inherits fd and mode from IO
    attr_accessor :filename
  public

  # f = File.new("testfile", "r")
  # f = File.new("newfile",  "w+")
  # f = File.new("newfile", File::CREAT|File::TRUNC|File::RDWR, 0644)
  # !!! I suppose I should figure out the correct default for perm..
  def initialize(name, mode='r', perm=0)
  end

  def path
    filename
  end

  # ctime/atime blah need fstat..
  # need lchown/chown/fchown, etc, etc

  # proxy these methods
  def File.basename(*a)
    ::File.basename(*a)
  end
  def File.dirname(*a)
    ::File.dirname(*a)
  end
  def File.extname(*a)
    ::File.extname(*a)
  end
  # !!! we might actually want to handle this File::SEPERATOR stuff
  # for win32 support, etc.
  def File.join(*a)
    ::File.join(*a)
  end

  def File.chmod
    raise NotImplementedError
  end
  def File.chown
    raise NotImplementedError
  end
  def File.delete(*a)
    unlink(*a)
  end
  def File.unlink
    raise NotImplementedError
  end
  def File.lchmod
    raise NotImplementedError
  end
  def File.lchown
    raise NotImplementedError
  end
  def File.link
    raise NotImplementedError
  end
  def File.lstat
    raise NotImplementedError
  end

  # this, along with all the other globbing/search stuff, probably
  # won't get implemented, atleast for a bit...
  def File.expand_path
    raise NotImplementedError
  end
  def File.fnmatch(*a)
    fnmatch?(*a)
  end
  def File.fnmatch?
    raise NotImplementedError
  end

  #
  # autogen'd stat passthroughs
  #
  def File.atime(name)
    stat(name).atime
  end
  def File.blockdev?(name)
    stat(name).blockdev?
  end
  def File.chardev?(name)
    stat(name).chardev?
  end
  def File.ctime(name)
    stat(name).ctime
  end
  def File.directory?(name)
    stat(name).directory?
  end
  def File.executable?(name)
    stat(name).executable?
  end
  def File.executable_real?(name)
    stat(name).executable_real?
  end
  def File.file?(name)
    stat(name).file?
  end
  def File.ftype(name)
    stat(name).ftype
  end
  def File.grpowned?(name)
    stat(name).grpowned?
  end
  def File.mtime(name)
    stat(name).mtime
  end
  def File.owned?(name)
    stat(name).owned?
  end
  def File.pipe?(name)
    stat(name).pipe?
  end
  def File.readable?(name)
    stat(name).readable?
  end
  def File.readable_real?(name)
    stat(name).readable_real?
  end
  def File.setuid?(name)
    stat(name).setuid?
  end
  def File.setgid?(name)
    stat(name).setgid?
  end
  def File.size(name)
    stat(name).size
  end
  def File.socket?(name)
    stat(name).socket?
  end
  def File.sticky?(name)
    stat(name).sticky?
  end
  def File.symlink?(name)
    stat(name).symlink?
  end
  def File.writeable?(name)
    stat(name).writeable?
  end
  def File.writeable_real?(name)
    stat(name).writeable_real?
  end
  def File.zero?(name)
    stat(name).zero?
  end

end

end; end # Post/Rex

