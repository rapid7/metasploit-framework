# -*- coding: binary -*-

module Msf

# This mixin provides helper functions for building Git repositories
module Exploit::Git

  class GitObject

    attr_reader :type, :content, :sha1, :path, :compressed

    def initialize(type, content, sha1, compressed)
      @type = type
      @content = content
      @sha1 = sha1
      @compressed = compressed
      @path = "#{@sha1[0...2]}/#{@sha1[2..40]}"
    end

    # Wrapper for `build_object()` to create
    # a GitObject of type `commit`
    # @param [ Hash ] containing sha1s for the tree,
    # (optional) parent sha1 and optional data
    # such as commit message, committer name,
    # company name, and email address
    def self.build_commit_object(opts = {})
      full_name = opts[:name] || Faker::Name.name
      email = opts[:email] || Faker::Internet.email(name: full_name, separators: ['-', '_'])
      company = opts[:company] || Faker::Company.name
      commit_text = opts[:message] || "Initial commit to open git repository for #{company}!"
      tree_sha1 = opts[:tree_sha1]
      parent_sha1 = opts[:parent_sha1]

      tstamp = Time.now.to_i
      author_time = rand(tstamp)
      commit_time = rand(author_time)
      tz_off = rand(10)

      commit_msg = "tree #{tree_sha1}\n"
      commit_msg << "parent #{parent_sha1}\n" unless parent_sha1.nil?
      commit_msg << "author #{full_name} <#{email}> #{author_time} -0#{tz_off}00\n"
      commit_msg << "committer #{full_name} <#{email}> #{commit_time} -0#{tz_off}00\n"
      commit_msg << "\n"
      commit_msg << "#{commit_text}\n"

      sha1, compressed = build_object('commit', commit_msg)
      GitObject.new('commit', commit_msg, sha1, compressed)
    end

    # Wrapper for `build_object()` to create
    # a GitObject of type `blob`
    # @param [ String ] the data that the object
    # will represent
    def self.build_blob_object(content)
      sha1, compressed = build_object('blob', content)
      GitObject.new('blob', content, sha1, compressed)
    end

    # Creates a GitObject of type `tree`
    # @param [ Hash ] entries containing
    # the file mode, name, and sha1 from
    # a previously-created `blob` object
    # Ex:
    # {
    #   mode: '100755', file_name: 'hooks',
    #   sha1: 'a372436ad8331b380e20e8c9861f547063d76a46'
    # }
    def self.build_tree_object(tree_entries)
      tree = ''
      unless tree_entries.is_a?(Array)
        tree_entries = [ tree_entries ]
      end

      tree_entries.each do |entry|
        tree += "#{entry[:mode]} #{entry[:file_name]}\0#{[entry[:sha1]].pack('H*')}"
      end

      sha1, compressed = build_object('tree', tree)
      GitObject.new('tree', tree, sha1, compressed)
    end

    # Generates a git object of the specified
    # type, ex: blob, tree, commit
    #
    # @param [ String ] type of object to create
    # @param [ String ] the data that the resulting
    # object will represent
    # Returns an Array containing the sha1 hash
    # and Zlib-compressed data
    def self.build_object(type, content)
      # taken from http://schacon.github.io/gitbook/7_how_git_stores_objects.html
      header = "#{type} #{content.size}\0"
      store = header + content
      [Digest::SHA1.hexdigest(store), Rex::Text.zlib_deflate(store, Zlib::DEFAULT_COMPRESSION)]
    end

    # Given a sha1 and list of Git objects
    # find the object with the matching sha1
    #
    # @param [ String ] sha1 of the object to find
    # @param [ Array ] list of GitObjects to search
    # @return GitObject with the matching sha1, nil otherwise
    def self.find_object(sha1, objs = [])
      return nil if objs.empty?

      objs.find { |obj| obj.sha1 == sha1 }
    end
  end
end
end
