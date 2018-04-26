module Msf

###
#
# This class hooks all session events and puts it into an RSS feed
#
###

class Plugin::EventRSS < Msf::Plugin

  attr_accessor :items, :queue, :queue_thread

  include Msf::SessionEvent

  def add_event(event)
    self.queue.push(event)
  end

  def generate_feed(newitem)
    items.unshift(newitem)
    feed = RSS::Maker.make("atom") do |maker|
      maker.channel.author = "msfconsole"
      maker.channel.updated = Time.new.to_s
      maker.channel.about = "https://metasploit.com"
      maker.channel.title = "msfconsole rss feed"

      items.each do |rssitem|
        maker.items.new_item do |item|
          item.link = rssitem[:link]
          item.title = rssitem[:title]
          item.updated = rssitem[:date]
          item.summary = rssitem[:content]
        end
      end
    end
    File.open("feed.rss", 'w') {|f| f.write(feed) }
  end

  def create_session_item(session, status)
    if status == "created" 
      select(nil, nil, nil, 25)
    end
    title = "#{session.type} session - #{session.sid} #{status}."
    content = ""
    if session.workspace
      content << "Workspace:\t#{session.workspace}\n"
    end
    content << "Session Information: #{session.info}"
    add_event({title: title, date: Time.now.to_s, link: "https://metasploit.com", content: content})
  end

  def on_session_open(session)
    create_session_item(session, "created")
  end

  def on_session_close(session, reason='')
    create_session_item(session, "closed")
  end

  def on_session_fail(reason='')
  end

  def on_plugin_load
    add_event({title: "RSS Plugin Loaded", date: Time.now.to_s, link: "https://metasploit.com/", content: "N/A"})
  end

  def on_plugin_unload
    generate_feed({title: "RSS Plugin Unloaded", date: Time.now.to_s, link: "https:/metasploit.com/", content: "N/A"})
  end

  def start_event_queue
    self.queue_thread = Rex::ThreadFactory.spawn("rss_plugin", false) do
      begin
      while(true)
        while(event = self.queue.shift)
          generate_feed(event)
        end
        select(nil, nil, nil, 0.25)
      end
      rescue ::Exception => e
        print_status("RSS plugin: fatal error #{e} #{e.backtrace}")
      end
    end
  end

  def stop_event_queue
    self.queue_thread.kill if self.queue_thread
    self.queue_thread = nil
    self.queue.clear
  end


  def initialize(framework, opts)
    require 'rss'
    super

    @items = []
    self.queue = Queue.new
    self.framework.events.add_session_subscriber(self)
    start_event_queue

    self.on_plugin_load
  end

  def cleanup
    self.on_plugin_unload
    self.framework.events.remove_session_subscriber(self)
    stop_event_queue
  end

  def name
    "rss"
  end

  def desc
    "Create an RSS feed of events"
  end

end
end
