# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/payload/uuid'
require 'json'

#
# This module provides a flat file database interface for managing UUIDs
#
class Msf::Payload::UUID::DB

  attr_accessor :info, :path

  def initialize(path)
    self.info = {}
    self.path = path
    @lock = Mutex.new
    @last = 0
    reload
  end

  # Save the file, but prevent thread & process contention
  def save(action={})
    @lock.synchronize do
      ::File.open(path, ::File::RDWR|::File::CREAT) do |fd|
        fd.flock(::File::LOCK_EX)

        # Reload and merge if the file has changed recently
        if fd.stat.mtime.to_f > @last
          self.info = parse_data(fd.read).merge(self.info)
        end

        if action[:register_uuid]
          params = (action[:params] || {}).merge({ type: 'uuid' })
          self.info[ action[:register_uuid] ] = params
        end

        if action[:register_url]
          params = (action[:params] || {}).merge({ type: 'url' })
          self.info[ action[:register_uurl] ] = params
        end

        if action[:remove_uuid]
          self.info.delete(action[:delete_uuid])
        end

        fd.rewind
        fd.write(JSON.pretty_generate(self.info))
        fd.sync
        fd.truncate(fd.pos)

        @last = Time.now.to_f
      end
    end
  end

  # Load the file from disk
  def load
    @lock.synchronize do
      ::File.open(path, ::File::RDWR|::File::CREAT) do |fd|
        fd.flock(::File::LOCK_EX)
        @last = fd.stat.mtime.to_f
        self.info = parse_data(fd.read(fd.stat.size))
      end
    end
  end

  # Reload if the file has changed
  def reload
    return unless ::File.exists?(path)
    return unless ::File.stat(path).mtime.to_f > @last
    load
  end

  def register_uuid(uuid, params)
    save(register_uuid: uuid, params: params)
  end

  def remove_uuid(uuid)
    save(remove_uuid: uuid)
  end

  def find_uuid(uuid)
    reload
    self.info[uuid]
  end

  def register_url(url, params)
    save(register_url: url, params: params)
  end

  def remove_url(url)
    save(remove_url: url)
  end

  def find_url(url)
    reload
    self.info[url]
  end

private

  def parse_data(data)
    return {} if data.to_s.strip.length == 0
    begin
      JSON.parse(data)
    rescue JSON::ParserError => e
      # TODO: Figure out the appropriate error handling path
      raise e
    end
  end

end


