module FSSM::State
  class Directory
    attr_reader :path

    def initialize(path, options={})
      @path    = path
      @options = options
      @cache   = FSSM::Tree::Cache.new
    end

    def refresh(base=nil, skip_callbacks=false)
      base_path = FSSM::Pathname.for(base || @path.to_pathname).expand_path
      previous, current = recache(base_path)

      unless skip_callbacks
        deleted(previous, current)
        created(previous, current)
        modified(previous, current)
      end
    end

    private

    def created(previous, current)
      (current.keys - previous.keys).sort.each do |file|
        @path.create(file, current[file][1])
      end
    end

    def deleted(previous, current)
      (previous.keys - current.keys).sort.reverse.each do |file|
        @path.delete(file, previous[file][1])
      end
    end

    def modified(previous, current)
      (current.keys & previous.keys).each do |file|
        current_data = current[file]
        @path.update(file, current_data[1]) if (current_data[0] <=> previous[file][0]) != 0
      end
    end

    def recache(base)
      base     = FSSM::Pathname.for(base)
      previous = cache_entries
      snapshot(base)
      current = cache_entries
      [previous, current]
    end

    def snapshot(base)
      base = FSSM::Pathname.for(base)
      @cache.unset(base)
      @path.glob.each { |glob| add_glob(base, glob) }
    end

    def add_glob(base, glob)
      FSSM::Pathname.glob(base.join(glob).to_s).each do |fn|
        @cache.set(fn)
      end
    end

    def cache_entries
      entries = tag_entries(@cache.files, :file)
      entries.merge! tag_entries(@cache.directories, :directory) if @options[:directories]
      entries
    end

    def tag_entries(entries, tag)
      tagged_entries = {}
      entries.each_pair { |fname, mtime| tagged_entries[fname] = [mtime, tag] }
      tagged_entries
    end
  end
end
