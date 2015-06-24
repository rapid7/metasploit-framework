# -*- coding => binary -*-

require 'json'
require 'fileutils'

#
# This class provides a thread-friendly hash file store in JSON format
#
module Rex
class JSONHashFile

  attr_accessor :path

  def initialize(path)
    self.path = path
    @lock = Mutex.new
    @hash = {}
    @last = 0
  end

  def [](k)
    synced_update
    @hash[k]
  end

  def []=(k,v)
    synced_update do
      @hash[k] = v
    end
  end

  def keys
    synced_update
    @hash.keys
  end

  def delete(k)
    synced_update do
      @hash.delete(k)
    end
  end

  def clear
    synced_update do
      @hash.clear
    end
  end

private

  # Save the file, but prevent thread & process contention
  def synced_update(&block)
    @lock.synchronize do
      ::FileUtils.mkdir_p(::File.dirname(path))
      ::File.open(path, ::File::RDWR|::File::CREAT) do |fd|
        fd.flock(::File::LOCK_EX)

        # Reload and merge if the file has changed recently
        if fd.stat.mtime.to_f > @last
          parse_data(fd.read).merge(@hash).each_pair do |k,v|
            @hash[k] = v
          end
        end

        res = nil

        # Update the file on disk if new data is written
        if block_given?
          res = block.call
          fd.rewind
          fd.write(JSON.pretty_generate(@hash))
          fd.sync
          fd.truncate(fd.pos)
        end

        @last = fd.stat.mtime.to_f

        res
      end
    end
  end

  def parse_data(data)
    return {} if data.to_s.strip.length == 0
    begin
      JSON.parse(data)
    rescue JSON::ParserError => e
      # elog("JSONHashFile @ #{path} was corrupt: #{e.class} #{e}"
      {}
    end
  end

end
end
