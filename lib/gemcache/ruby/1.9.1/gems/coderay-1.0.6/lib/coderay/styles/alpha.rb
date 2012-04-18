module CodeRay
module Styles
  
  # A colorful theme using CSS 3 colors (with alpha channel).
  class Alpha < Style

    register_for :alpha

    code_background = 'hsl(0,0%,95%)'
    numbers_background = 'hsl(180,65%,90%)'
    border_color = 'silver'
    normal_color = 'black'

    CSS_MAIN_STYLES = <<-MAIN  # :nodoc:
.CodeRay {
  background-color: #{code_background};
  border: 1px solid #{border_color};
  color: #{normal_color};
}
.CodeRay pre {
  margin: 0px;
}

span.CodeRay { white-space: pre; border: 0px; padding: 2px; }

table.CodeRay { border-collapse: collapse; width: 100%; padding: 2px; }
table.CodeRay td { padding: 2px 4px; vertical-align: top; }

.CodeRay .line-numbers {
  background-color: #{numbers_background};
  color: gray;
  text-align: right;
  -webkit-user-select: none;
  -moz-user-select: none;
  user-select: none;
}
.CodeRay .line-numbers a {
  background-color: #{numbers_background} !important;
  color: gray !important;
  text-decoration: none !important;
}
.CodeRay .line-numbers a:target { color: blue !important; }
.CodeRay .line-numbers .highlighted { color: red !important; }
.CodeRay .line-numbers .highlighted a { color: red !important; }
.CodeRay span.line-numbers { padding: 0px 4px; }
.CodeRay .line { display: block; float: left; width: 100%; }
.CodeRay .code { width: 100%; }
    MAIN

    TOKEN_COLORS = <<-'TOKENS'
.debug { color: white !important; background: blue !important; }

.annotation { color:#007 }
.attribute-name { color:#b48 }
.attribute-value { color:#700 }
.binary { color:#509 }
.char .content { color:#D20 }
.char .delimiter { color:#710 }
.char { color:#D20 }
.class { color:#B06; font-weight:bold }
.class-variable { color:#369 }
.color { color:#0A0 }
.comment { color:#777 }
.comment .char { color:#444 }
.comment .delimiter { color:#444 }
.complex { color:#A08 }
.constant { color:#036; font-weight:bold }
.decorator { color:#B0B }
.definition { color:#099; font-weight:bold }
.delimiter { color:black }
.directive { color:#088; font-weight:bold }
.doc { color:#970 }
.doc-string { color:#D42; font-weight:bold }
.doctype { color:#34b }
.entity { color:#800; font-weight:bold }
.error { color:#F00; background-color:#FAA }
.escape  { color:#666 }
.exception { color:#C00; font-weight:bold }
.float { color:#60E }
.function { color:#06B; font-weight:bold }
.global-variable { color:#d70 }
.hex { color:#02b }
.imaginary { color:#f00 }
.include { color:#B44; font-weight:bold }
.inline { background-color: hsla(0,0%,0%,0.07); color: black }
.inline-delimiter { font-weight: bold; color: #666 }
.instance-variable { color:#33B }
.integer  { color:#00D }
.key .char { color: #60f }
.key .delimiter { color: #404 }
.key { color: #606 }
.keyword { color:#080; font-weight:bold }
.label { color:#970; font-weight:bold }
.local-variable { color:#963 }
.namespace { color:#707; font-weight:bold }
.octal { color:#40E }
.operator { }
.predefined { color:#369; font-weight:bold }
.predefined-constant { color:#069 }
.predefined-type { color:#0a5; font-weight:bold }
.preprocessor { color:#579 }
.pseudo-class { color:#00C; font-weight:bold }
.regexp .content { color:#808 }
.regexp .delimiter { color:#404 }
.regexp .modifier { color:#C2C }
.regexp { background-color:hsla(300,100%,50%,0.06); }
.reserved { color:#080; font-weight:bold }
.shell .content { color:#2B2 }
.shell .delimiter { color:#161 }
.shell { background-color:hsla(120,100%,50%,0.06); }
.string .char { color: #b0b }
.string .content { color: #D20 }
.string .delimiter { color: #710 }
.string .modifier { color: #E40 }
.string { background-color:hsla(0,100%,50%,0.05); }
.symbol .content { color:#A60 }
.symbol .delimiter { color:#630 }
.symbol { color:#A60 }
.tag { color:#070 }
.type { color:#339; font-weight:bold }
.value { color: #088; }
.variable  { color:#037 }

.insert { background: hsla(120,100%,50%,0.12) }
.delete { background: hsla(0,100%,50%,0.12) }
.change { color: #bbf; background: #007; }
.head { color: #f8f; background: #505 }
.head .filename { color: white; }

.delete .eyecatcher { background-color: hsla(0,100%,50%,0.2); border: 1px solid hsla(0,100%,45%,0.5); margin: -1px; border-bottom: none; border-top-left-radius: 5px; border-top-right-radius: 5px; }
.insert .eyecatcher { background-color: hsla(120,100%,50%,0.2); border: 1px solid hsla(120,100%,25%,0.5); margin: -1px; border-top: none; border-bottom-left-radius: 5px; border-bottom-right-radius: 5px; }

.insert .insert { color: #0c0; background:transparent; font-weight:bold }
.delete .delete { color: #c00; background:transparent; font-weight:bold }
.change .change { color: #88f }
.head .head { color: #f4f }
    TOKENS

  end

end
end
