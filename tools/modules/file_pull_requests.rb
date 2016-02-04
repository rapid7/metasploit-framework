#!/usr/bin/env ruby

require 'octokit'
require 'net/http'
require 'nokogiri'
require 'optparse'

module FilePullRequestCollector

  class Exception < RuntimeError; end

  class PullRequestFinder

    attr_accessor :git_client
    attr_accessor :repository
    attr_accessor :branch
    attr_accessor :owner
    attr_accessor :git_access_token

    def initialize(api_key)
      self.owner            = 'rapid7'
      self.repository       = "#{owner}/metasploit-framework"
      self.branch           = 'master'
      self.git_access_token = api_key
      self.git_client       = Octokit::Client.new(access_token: git_access_token)
    end

    # Returns the commit history of a file.
    def get_commits_from_file(path)
      commits = git_client.commits(repository, branch, path: path)
      if commits.empty?
        # Possibly the path is wrong.
        raise FilePullRequestCollector::Exception, 'No commits found.'
      end

      commits
    end

    def get_author(commit)
      if commit.author
        return commit.author[:login].to_s
      end

      ''
    end

    def is_author_blacklisted?(commit)
      ['tabassassin'].include?(get_author(commit))
    end

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

  class Client

    attr_accessor :finder

    def initialize(api_key)
      self.finder = PullRequestFinder.new(api_key)
    end

    def search(file_name)
      commits = finder.get_commits_from_file(file_name)
      pull_requests = finder.get_pull_requests_from_commits(commits)
      puts "Pull request(s) associated with #{file_name}"
      pull_requests.each_pair do |number, pr|
        puts "##{number} - #{pr[:title]}"
      end
    end
  end

  class OptsParser

    def self.banner
      %Q|
      This tool collects all the pull requests submitted to rapid7/metasploit-framework for a
      particular file. It does not include history from SVN (what Metasploit used to use
      before Git).

      Usage: #{__FILE__} [options]

      Usage Example:
      #{__FILE__} -k KEY -f modules/exploits/windows/browser/ms13_069_caret.rb

      How to obtain an API key (access token):
      1. Go to github.com.
      2. Go to Settings under your profile.
      3. Click on Personal Access Tokens
      4. Click on Generate new token
      5. Follow the steps on the screen to complete the process.

      |
    end

    def self.parse(args)
      options = {}

      opts = OptionParser.new do |opts|
        opts.banner = banner.strip.gsub(/^[[:blank:]]{4}/, '')

        opts.separator ""
        opts.separator "Specific options:"

        opts.on("-k", "-k <key>", "Github Access Token") do |v|
          options[:api_key] = v
        end

        opts.on("-f", "--file <name>", "File name") do |v|
          options[:file] = v
        end

        opts.separator ""
        opts.separator "Common options:"

        opts.on_tail("-h", "--help", "Show this message") do
          puts opts
          exit
        end
      end

      begin
        opts.parse!(args)
      rescue OptionParser::InvalidOption
        puts "Invalid option, try -h for usage"
        exit
      end

      if options.empty?
        puts "No options specified, try -h for usage" 
        exit
      end

      options
    end
  end

end

if __FILE__ == $PROGRAM_NAME
  begin
    opts = FilePullRequestCollector::OptsParser.parse(ARGV)
  rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
    puts "#{e.message} (please see -h)"
    exit
  end

  begin
    cli = FilePullRequestCollector::Client.new(opts[:api_key])
    cli.search(opts[:file])
  rescue FilePullRequestCollector::Exception => e
    $stderr.puts e.message
    exit
  rescue Interrupt
    $stdout.puts
    $stdout.puts "Good bye"
  end
end
