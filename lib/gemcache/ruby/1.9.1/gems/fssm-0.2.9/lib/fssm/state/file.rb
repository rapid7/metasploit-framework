module FSSM::State
  class File
    attr_reader :path

    def initialize(path)
      @path = path
    end

    def refresh(base=nil, skip_callbacks=false)
      base ||= @path.to_pathname
      used_to_exist, @exists = @exists, base.exist?
      # this handles bad symlinks without failing. why handle bad symlinks at
      # all? well, we could still be interested in their creation and deletion.
      old_mtime, @mtime = @mtime, base.symlink? ? Time.at(0) : base.mtime if @exists

      unless skip_callbacks
        @path.delete(@path.to_s) if used_to_exist && !@exists
        @path.create(@path.to_s) if !used_to_exist && @exists
        @path.update(@path.to_s) if used_to_exist && @exists && old_mtime != @mtime
      end
    end

  end
end
