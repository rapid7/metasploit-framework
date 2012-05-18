#!/usr/bin/env rackup -s thin
# 
#  async_chat.ru
#  raggi/thin
#  
#  Created by James Tucker on 2008-06-19.
#  Copyright 2008 James Tucker <raggi@rubyforge.org>.

# Uncomment if appropriate for you..
EM.epoll
# EM.kqueue # bug on OS X in 0.12?

class DeferrableBody
  include EventMachine::Deferrable
  
  def initialize
    @queue = []
  end
  
  def schedule_dequeue
    return unless @body_callback
    EventMachine::next_tick do
      next unless body = @queue.shift
      body.each do |chunk|
        @body_callback.call(chunk)
      end
      schedule_dequeue unless @queue.empty?
    end
  end 

  def call(body)
    @queue << body
    schedule_dequeue
  end

  def each &blk
    @body_callback = blk
    schedule_dequeue
  end

end

class Chat
  
  module UserBody
    attr_accessor :username
  end
  
  def initialize
    @users = {}
  end
  
  def render_page
    [] << <<-EOPAGE
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
  <html>
    <head>
      <style>
        body {
          font-family: sans-serif;
          margin: 0; 
          padding: 0;
          margin-top: 4em;
          margin-bottom: 1em;
        }
        #header {
          background: silver;
          height: 4em;
          width: 100%;
          position: fixed;
          top: 0px;
          border-bottom: 1px solid black;
          padding-left: 0.5em;
        }
        #messages {
          width: 100%;
          height: 100%;
        }
        .message {
          margin-left: 1em;
        }
        #send_form {
          position: fixed;
          bottom: 0px;
          height: 1em;
          width: 100%;
        }
        #message_box {
          background: silver;
          width: 100%;
          border: 0px;
          border-top: 1px solid black;
        }
        .gray {
          color: gray;
        }
      </style>
      <script type="text/javascript" src="http://ra66i.org/tmp/jquery-1.2.6.min.js"></script>
      <script type="text/javascript">
        XHR = function() {
          var request = false;
          try { request = new ActiveXObject('Msxml2.XMLHTTP');    } catch(e) {
            try { request = new ActiveXObject('Microsoft.XMLHTTP'); } catch(e1) {
      		    try {	request = new XMLHttpRequest();                 	}	catch(e2) { 
      		      return false; 
    		      }
  		      }
  	      }
          return request;
        }
        scroll = function() {
        	window.scrollBy(0,50);
        	setTimeout('scroll()',100);
        }
        focus = function() {
          $('#message_box').focus();
        }
        send_message = function(message_box) {
          xhr = XHR();
          xhr.open("POST", "/", true); 
      		xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      		xhr.setRequestHeader("X_REQUESTED_WITH", "XMLHttpRequest");
      		xhr.send("message="+escape(message_box.value));
          scroll();
          message_box.value = '';
          focus();
          return false;
        }
        new_message = function(username, message) {
          // TODO html escape message
          formatted_message = "<div class='message'>" + username + ": " + message + "</div>";
          messages_div = $('#messages');
          $(formatted_message).appendTo(messages_div);
          scroll();
          return true;
        }
      </script>
      <title>Async Chat</title>
    </head>
    <body>
      <div id="header">
        <h1>Async Chat</h1>
      </div>
      <div id="messages" onclick="focus();">
        <span class="gray">Your first message will become your nickname!</span>
        <span>Users: #{@users.map{|k,u|u.username}.join(', ')}</span>
      </div>
      <form id="send_form" onSubmit="return send_message(this.message)">
        <input type="text" id="message_box" name="message"></input>
      </form>
      <script type="text/javascript">focus();</script>
    </body>
  </html>
  EOPAGE
  end
  
  def register_user(user_id, renderer)
    body = create_user(user_id)
    body.call render_page
    body.errback { delete_user user_id }
    body.callback { delete_user user_id }
    
    EventMachine::next_tick do
      renderer.call [200, {'Content-Type' => 'text/html'}, body]
    end
  end
  
  def new_message(user_id, message)
    return unless @users[user_id]
    if @users[user_id].username == :anonymous
      username = unique_username(message)
      log "User: #{user_id} is #{username}"
      @users[user_id].username = message
      message = "<span class='gray'>-> #{username} signed on.</span>"
    end
    username ||= @users[user_id].username
    log "User: #{username} sent: #{message}"
    @users.each do |id, body|
      EventMachine::next_tick { body.call [js_message(username, message)] }
    end
  end
  
  private
  def unique_username(name)
    name.concat('_') while @users.any? { |id,u| name == u.username }
    name
  end
  
  def log(str)
    print str, "\n"
  end
  
  def add_user(id, body)
    @users[id] = body
  end
  
  def delete_user(id)
    message = "User: #{id} - #{@users[id].username if @users[id]} disconnected."
    log message
    new_message(id, message)
    @users.delete id
  end
  
  def js_message(username, message)
    %(<script type="text/javascript">new_message("#{username}","#{message}");</script>)
  end
  
  def create_user(id)
    message = "User: #{id} connected."
    log message
    new_message(id, message)
    body = DeferrableBody.new
    body.extend UserBody
    body.username = :anonymous
    add_user(id, body)
    body
  end
  
end

class AsyncChat
  
  AsyncResponse = [-1, {}, []].freeze
  AjaxResponse = [200, {}, []].freeze
  
  def initialize
    @chat = Chat.new
  end
  
  def call(env)  
    request = Rack::Request.new(env)
    # TODO - cookie me, baby
    user_id = request.env['REMOTE_ADDR']
    if request.xhr?
      message = request['message']
      @chat.new_message(user_id, Rack::Utils.escape_html(message))
      AjaxResponse
    else
      renderer = request.env['async.callback']
      @chat.register_user(user_id, renderer)
      AsyncResponse
    end
  end
  
end

run AsyncChat.new
