require 'yaml'
require 'redcloth'

def process_faq_list( faqs )
  puts "<ul>"
  faqs.each do |faq|
    process_faq_list_item faq
  end
  puts "</ul>"
end

def process_faq_list_item( faq )
  question = faq.keys.first
  answer = faq.values.first

  print "<li>"

  question_text = RedCloth.new(question).to_html.gsub( %r{</?p>},"" )
  if answer.is_a?( Array )
    puts question_text
    process_faq_list answer
  else
    print "<a href='##{question.object_id}'>#{question_text}</a>"
  end

  puts "</li>"
end

def process_faq_descriptions( faqs, path=nil )
  faqs.each do |faq|
    process_faq_description faq, path
  end
end

def process_faq_description( faq, path )
  question = faq.keys.first
  path = ( path ? path + " " : "" ) + question
  answer = faq.values.first

  if answer.is_a?( Array )
    process_faq_descriptions( answer, path )
  else
    title = RedCloth.new( path ).to_html.gsub( %r{</?p>}, "" )
    answer = RedCloth.new( answer || "" )

    puts "<a name='#{question.object_id}'></a>"
    puts "<div class='faq-title'>#{title}</div>"
    puts "<div class='faq-answer'>#{add_api_links(answer.to_html)}</div>"
  end
end

API_OBJECTS = [ "Database", "Statement", "ResultSet",
  "ParsedStatement", "Pragmas", "Translator" ].inject( "(" ) { |acc,name|
    acc << "|" if acc.length > 1
    acc << name
    acc
  } + ")"

def add_api_links( text )
  text.gsub( /#{API_OBJECTS}(#(\w+))?/ ) do
    disp_obj = obj = $1

    case obj
      when "Pragmas"; disp_obj = "Database"
    end

    method = $3
    s = "<a href='http://sqlite-ruby.rubyforge.org/classes/SQLite/#{obj}.html'>#{disp_obj}"
    s << "##{method}" if method
    s << "</a>"
    s
  end
end

faqs = YAML.load( File.read( "faq.yml" ) )

puts <<-EOF
<html>
  <head>
    <title>SQLite3/Ruby FAQ</title>
    <style type="text/css">
      a, a:visited, a:active {
        color: #00F;
        text-decoration: none;
      }

      a:hover {
        text-decoration: underline;
      }

      .faq-list {
        color: #000;
        font-family: vera-sans, verdana, arial, sans-serif;
      }

      .faq-title {
        background: #007;
        color: #FFF;
        font-family: vera-sans, verdana, arial, sans-serif;
        padding-left: 1em;
        padding-top: 0.5em;
        padding-bottom: 0.5em;
        font-weight: bold;
        font-size: large;
        border: 1px solid #000;
      }

      .faq-answer {
        margin-left: 1em;
        color: #000;
        font-family: vera-sans, verdana, arial, sans-serif;
      }

      .faq-answer pre {
        margin-left: 1em;
        color: #000;
        background: #FFE;
        font-size: normal;
        border: 1px dotted #CCC;
        padding: 1em;
      }

      h1 {
        background: #005;
        color: #FFF;
        font-family: vera-sans, verdana, arial, sans-serif;
        padding-left: 1em;
        padding-top: 1em;
        padding-bottom: 1em;
        font-weight: bold;
        font-size: x-large;
        border: 1px solid #00F;
      }
    </style>
  </head>
  <body>
  <h1>SQLite/Ruby FAQ</h1>
  <div class="faq-list">
EOF

process_faq_list( faqs )
puts "</div>"
process_faq_descriptions( faqs )

puts "</body></html>"
