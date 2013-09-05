# -*- coding: binary -*-

##
# Rex::OLE - an OLE implementation
# written in 2010 by Joshua J. Drake <jduck [at] metasploit.com>
##

module Rex
module OLE

require 'rex/ole/direntry'

#
# This class serves as the root directory entry in addition to
# an abstraction around the concept of a directory as a whole.
#
class Directory < DirEntry

  # XXX: num_entries is not maintained once a stream/storage is added!
  attr_accessor :num_entries

  def initialize(stg)
    super

    @num_entries = 1
  end


  # woop, recursive each
  def yield_entries(de, &block)
    block.call(de)
    de.each { |el|
      yield_entries(el, &block)
    }
  end
  def each_entry(&block)
    yield_entries(self, &block)
  end


  def set_ministream_params(start, size)
    @_sectStart = start
    @_ulSize = size
  end

  def link_item(parent, child)
    # set sid, advance count
    child.sid = @num_entries
    @num_entries += 1

    # link item to siblings and/or parent
    if (parent._sidChild == DIR_NOSTREAM)
      parent._sidChild = child.sid
      dlog("Linking #{child.name} as THE child of #{parent.name} as sid #{child.sid}", 'rex', LEV_3)
    else
      sib = nil
      parent.each { |el|
        if (el._sidLeftSib == DIR_NOSTREAM)
          sib = el
          el._sidLeftSib = child.sid
          dlog("Linking #{child.name} as the LEFT sibling of #{sib.name} as sid #{child.sid}", 'rex', LEV_3)
          break
        end
        if (el._sidRightSib == DIR_NOSTREAM)
          sib = el
          el._sidRightSib = child.sid
          dlog("Linking #{child.name} as the RIGHT sibling of #{sib.name} as sid #{child.sid}", 'rex', LEV_3)
          break
        end
      }
      if (not sib)
        raise RuntimeError, 'Unable to find a sibling to link to in the directory'
      end
    end
    parent << child
  end


  #
  # low-level functions
  #
  def from_s(sid, buf)
    super

    if (@_sidRightSib != DIR_NOSTREAM)
      raise RuntimeError, 'Root Entry is invalid! (has right sibling)'
    end
    if (@_sidLeftSib != DIR_NOSTREAM)
      raise RuntimeError, 'Root Entry is invalid! (has left sibling)'
    end
  end

  def read
    @children = []
    visited = []
    entries = []
    root_node = nil
    sect = @stg.header._sectDirStart
    while (sect != SECT_END)

      if (visited.include?(sect))
        raise RuntimeError, 'Sector chain loop detected (0x%08x)' % sect
      end
      visited << sect

      sbuf = @stg.read_sector(sect, @stg.header.sector_size)
      while (sbuf.length >= DIRENTRY_SZ)
        debuf = sbuf.slice!(0, DIRENTRY_SZ)

        type = Util.get8(debuf, 0x42)
        case type
        when STGTY_ROOT
          if (entries.length != 0)
            raise RuntimeError, 'Root Entry found, but not first encountered!'
          end
          if (root_node)
            raise RuntimeError, 'Multiple root directory sectors detected (0x%08x)' % sect
          end
          de = self
          root_node = de

        when STGTY_STORAGE
          de = SubStorage.new @stg

        when STGTY_STREAM
          de = Stream.new @stg

        when STGTY_INVALID
          # skip invalid entries
          next

        else
          raise RuntimeError, 'Unsupported directory entry type (0x%02x)' % type
        end

        # read content
        de.from_s(entries.length, debuf)
        entries << de
      end
      sect = @stg.next_sector(sect)
    end

    @num_entries = entries.length

    # sort out the tree structure, starting with the root
    if (@_sidChild != DIR_NOSTREAM)
      populate_children(entries, root_node, @_sidChild)
    end
  end


  # recursively add entries to their proper parents :)
  def populate_children(entries, parent, sid)
    node = entries[sid]
    dlog("populate_children(entries, \"#{parent.name}\", #{sid}) - node: #{node.name}", 'rex', LEV_3)
    parent << node
    if (node.type == STGTY_STORAGE) and (node._sidChild != DIR_NOSTREAM)
      populate_children(entries, node, node._sidChild)
    end
    if (node._sidLeftSib != DIR_NOSTREAM)
      populate_children(entries, parent, node._sidLeftSib)
    end
    if (node._sidRightSib != DIR_NOSTREAM)
      populate_children(entries, parent, node._sidRightSib)
    end
  end

  # NOTE: this may not be necessary if we were to use each_entry
  def flatten_tree(entries, parent)
    entries << parent
    parent.each { |el|
      flatten_tree(entries, el)
    }
  end


  def write
    # flatten the directory again
    entries = []
    flatten_tree(entries, self)
    dlog("flattened tree has #{entries.length} entries...", 'rex', LEV_3)

    # count directory sectors
    ds_count = entries.length / 4
    if ((entries.length % 4) > 0)
      # one more sector to hold the rest
      ds_count += 1
    end

    # put the root entry first
    sbuf = self.pack

    # add the rest
    prev_sect = nil
    dir_start = nil
    entries.each { |de|
      # we already got the root entry, no more!
      next if (de.type == STGTY_ROOT)

      dir = de.pack
      dlog("writing dir entry #{de.name}", 'rex', LEV_3)
      sbuf << dir

      if (sbuf.length == @stg.header.sector_size)
        # we have a full sector, add it!
        sect = @stg.write_sector(sbuf, nil, prev_sect)
        prev_sect = sect
        dir_start ||= sect
        # reset..
        sbuf = ""
      end
    }

    # still a partial sector left?
    if (sbuf.length > 0)
      # add it! (NOTE: it will get padded with nul bytes if its not sector sized)
      sect = @stg.write_sector(sbuf, nil, prev_sect)
      prev_sect = sect
      dir_start ||= sect
    end

    @stg.header._sectDirStart = dir_start
  end

end

end
end
