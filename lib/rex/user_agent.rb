# -*- coding: binary -*-

#
# A helper module for using and referencing coming user agent strings.
#
module Rex::UserAgent

  #
  # Taken from https://www.whatismybrowser.com/guides/the-latest-user-agent/
  #
  COMMON_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36', # Chrome Windows
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36', # Chrome MacOS

    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/131.0.2903.86', # Edge Windows

    'Mozilla/5.0 (iPad; CPU OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1', # Safari iPad
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15', # Safari MacOS

    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0', # Firefox Windows
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:135.0) Gecko/20100101 Firefox/135.0' # Firefox MacOS
  ]

  #
  # A randomly-selected agent that will be consistent for the duration of metasploit running
  #
  def self.session_agent
    if @@session_agent
      @@session_agent
    else
      @@session_agent = self.random
    end
  end

  @@session_agent = nil

  #
  # Pick a random agent from the common agent list.
  #
  def self.random
    COMMON_AGENTS.sample
  end

  #
  # Choose the agent with the shortest string (for use in payloads)
  #
  def self.shortest
    @@shortest_agent ||= COMMON_AGENTS.min { |a, b| a.size <=> b.size }
  end

  #
  # Choose the most frequent user agent
  #
  def self.most_common
    COMMON_AGENTS[0]
  end

end
