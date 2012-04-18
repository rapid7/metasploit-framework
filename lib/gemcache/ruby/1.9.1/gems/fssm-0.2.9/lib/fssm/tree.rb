module FSSM::Tree
  module NodeBase
    def initialize
      @children = {}
    end

    protected

    def child(segment)
      @children["#{segment}"]
    end

    def child!(segment)
      (@children["#{segment}"] ||= Node.new)
    end

    def has_child?(segment)
      @children.has_key?("#{segment}")
    end

    def remove_child(segment)
      @children.delete("#{segment}")
    end

    def remove_children
      @children.clear
    end
  end

  module NodeEnumerable
    include NodeBase
    include Enumerable

    def each(prefix=nil, &block)
      @children.each do |segment, node|
        cprefix = prefix ?
            FSSM::Pathname.for(prefix).join(segment) :
            FSSM::Pathname.for(segment)
        block.call([cprefix, node])
        node.each(cprefix, &block)
      end
    end
  end

  module NodeInsertion
    include NodeBase

    def unset(path)
      key = key_segments(path)

      if key.empty?
        remove_children
        return nil
      end

      segment = key.pop
      node    = descendant(key)

      return unless node

      node.remove_child(segment)

      nil
    end

    def set(path)
      node = descendant!(path)
      node.from_path(path).mtime
    end

    protected

    def key_segments(key)
      return key if key.is_a?(Array)
      FSSM::Pathname.for(key).segments
    end

    def descendant(path)
      recurse(path, false)
    end

    def descendant!(path)
      recurse(path, true)
    end

    def recurse(key, create=false)
      key  = key_segments(key)
      node = self

      until key.empty?
        segment = key.shift
        node    = create ? node.child!(segment) : node.child(segment)
        return nil unless node
      end

      node
    end
  end

  module CacheDebug
    def set(path)
      FSSM.dbg("Cache#set(#{path})")
      super
    end

    def unset(path)
      FSSM.dbg("Cache#unset(#{path})")
      super
    end

    def ftype(ft)
      FSSM.dbg("Cache#ftype(#{ft})")
      super
    end
  end

  class Node
    include NodeBase
    include NodeEnumerable

    attr_accessor :mtime
    attr_accessor :ftype

    def <=>(other)
      return unless other.is_a?(::FSSM::Tree::Node)
      self.mtime <=> other.mtime
    end

    def from_path(path)
      path   = FSSM::Pathname.for(path)
      @ftype = path.ftype
      # this handles bad symlinks without failing. why handle bad symlinks at
      # all? well, we could still be interested in their creation and deletion.
      @mtime = path.symlink? ? Time.at(0) : path.mtime
      self
    end
  end

  class Cache
    include NodeBase
    include NodeEnumerable
    include NodeInsertion
    include CacheDebug if $DEBUG

    def set(path)
      # all paths set from this level need to be absolute
      # realpath will fail on broken links
      path = FSSM::Pathname.for(path).expand_path
      super(path)
    end

    def files
      ftype('file')
    end

    def directories
      ftype('directory')
    end

    def links
      ftype('link')
    end

    alias symlinks links

    private

    def ftype(ft)
      inject({}) do |hash, (path, node)|
        hash["#{path}"] = node.mtime if node.ftype == ft
        hash
      end
    end
  end

end
