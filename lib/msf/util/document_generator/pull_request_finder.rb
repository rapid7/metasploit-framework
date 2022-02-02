require 'octokit'
require 'nokogiri'
require 'net/http'

module Msf
  module Util
    module DocumentGenerator

      class PullRequestFinder

        class Exception < RuntimeError; end

        MANUAL_BASE_PATH = File.expand_path(File.join(Msf::Config.module_directory, '..', 'documentation', 'modules' ))
        USER_MANUAL_BASE_PATH = File.expand_path(File.join(Msf::Config.user_module_directory, '..', 'documentation', 'modules' ))

        # @return [Octokit::Client] Git client
        attr_accessor :git_client

        # @return [String] Metasploit Framework's repository
        attr_accessor :repository

        # @return [String] Metasploit Framework's branch
        attr_accessor :branch

        # @return [String] Metasploit Framework's repository owner
        attr_accessor :owner

        # @return [String] Git access token
        attr_accessor :git_access_token


        # Initializes Msf::Util::DocumenGenerator::PullRequestFinder
        #
        # @raise [PullRequestFinder::Exception] No GITHUB_OAUTH_TOKEN environment variable
        # @return [void]
        def initialize
          unless ENV.has_key?('GITHUB_OAUTH_TOKEN')
            msg = ''
            raise PullRequestFinder::Exception, 'GITHUB_OAUTH_TOKEN environment variable not set.'
          end

          self.owner            = 'rapid7'
          self.repository       = "#{owner}/metasploit-framework"
          self.branch           = 'master'
          self.git_access_token = ENV['GITHUB_OAUTH_TOKEN']
          self.git_client       = Octokit::Client.new(access_token: git_access_token)
        end


        # Returns pull requests associated with a particular Metasploit module.
        #
        # @param mod [Msf::Module] Metasploit module.
        # @return [Hash]
        def search(mod)
          file_name = get_normalized_module_name(mod)
          commits = get_commits_from_file(file_name)
          get_pull_requests_from_commits(commits)
        end


        private


        # Returns the normalized module full name.
        #
        # @param mod [Msf::Module] Metasploit module.
        # @return [String]
        def get_normalized_module_name(mod)
          source_fname = mod.method(:initialize).source_location.first
          source_fname.scan(/(modules.+)/).flatten.first || ''
        end


        # Returns git commits for a particular file.
        #
        # @param path [String] File path.
        # @raise [PullRequestFinder::Exception] No commits found.
        # @return [Array<Sawyer::Resource>]
        def get_commits_from_file(path)
          begin
            commits = git_client.commits(repository, branch, path: path)
          rescue Faraday::ConnectionFailed
            raise PullRequestFinder::Exception, 'No network connection to Github.'
          end

          if commits.empty?
            # Possibly the path is wrong.
            raise PullRequestFinder::Exception, 'No commits found.'
          end

          commits
        end


        # Returns the author for the commit.
        #
        # @param commit [Sawyer::Resource]
        # @return [String]
        def get_author(commit)
          if commit.author
            return commit.author[:login].to_s
          end

          ''
        end


        # Checks whether the author should be skipped or not.
        #
        # @param commit [Sawyer::Resource]
        # @return [Boolean] TrueClass if the author should be skipped, otherwise false.
        def is_author_blacklisted?(commit)
          ['tabassassin'].include?(get_author(commit))
        end


        # Returns unique pull requests for a collection of commits.
        #
        # @param commits [Array<Sawyer::Resource>]
        # @return [Hash]
        def get_pull_requests_from_commits(commits)
          pull_requests = {}

          commits.each do |commit|
            next if is_author_blacklisted?(commit)

            pr = get_pull_request_from_commit(commit)
            unless pr.empty?
              pull_requests[pr[:number]] = pr
            end
          end

          pull_requests
        end


        # Returns unique pull requests for a commit.
        #
        # @param commit [Sawyer::Resource]
        # @return [Hash]
        def get_pull_request_from_commit(commit)
          sha = commit.sha
          url = URI.parse("https://github.com/#{repository}/branch_commits/#{sha}")
          cli = Net::HTTP.new(url.host, url.port)
          cli.use_ssl = true
          req = Net::HTTP::Get.new(url.request_uri)
          res = cli.request(req)
          n = Nokogiri::HTML(res.body)
          found_pr_link = n.at('li[@class="pull-request"]//a')

          # If there is no PR associated with this commit, it's probably from the SVN days.
          return {} unless found_pr_link

          href  = found_pr_link.attributes['href'].text
          title = found_pr_link.attributes['title'].text

          # Filter out all the pull requests that do not belong to rapid7.
          # If this happens, it's probably because the PR was submitted to somebody's fork.
          return {} unless /^\/#{owner}\// === href

          { number: href.scan(/\d+$/).flatten.first, title: title }
        end
      end

    end
  end
end
