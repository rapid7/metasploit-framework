# Sinatra

*Wichtig: Dieses Dokument ist eine Übersetzung aus dem Englischen und unter
Umständen nicht auf dem aktuellen Stand (aktuell Sinatra 1.4.5).*

Sinatra ist eine
[DSL](https://de.wikipedia.org/wiki/Domänenspezifische_Sprache), die das
schnelle Erstellen von Webanwendungen in Ruby mit minimalem Aufwand
ermöglicht:

Sinatra via `rubygems` installieren:

```shell
gem install sinatra
```

Eine Datei mit dem Namen `myapp.rb` erstellen:

```ruby
require 'sinatra'
get '/' do
  'Hallo Welt!'
end
```

und im gleichen Verzeichnis ausführen:

```shell
ruby myapp.rb
```

Die Seite kann nun unter [http://localhost:4567](http://localhost:4567)
aufgerufen werden.

## Inhalt

* [Sinatra](#sinatra)
    * [Routen](#routen)
        * [Bedingungen](#bedingungen)
        * [Rückgabewerte](#rckgabewerte)
        * [Eigene Routen-Muster](#eigene-routen-muster)
    * [Statische Dateien](#statische-dateien)
    * [Views/Templates](#viewstemplates)
        * [Direkte Templates](#direkte-templates)
        * [Verfügbare Templatesprachen](#verfgbare-templatesprachen)
            * [Haml Templates](#haml-templates)
            * [Erb Templates](#erb-templates)
            * [Builder Templates](#builder-templates)
            * [Nokogiri Templates](#nokogiri-templates)
            * [Sass Templates](#sass-templates)
            * [SCSS Templates](#scss-templates)
            * [Less Templates](#less-templates)
            * [Liquid Templates](#liquid-templates)
            * [Markdown Templates](#markdown-templates)
            * [Textile Templates](#textile-templates)
            * [RDoc Templates](#rdoc-templates)
            * [AsciiDoc Templates](#asciidoc-templates)
            * [Radius Templates](#radius-templates)
            * [Markaby Templates](#markaby-templates)
            * [RABL Templates](#rabl-templates)
            * [Slim Templates](#slim-templates)
            * [Creole Templates](#creole-templates)
            * [MediaWiki Templates](#mediawiki-templates)
            * [CoffeeScript Templates](#coffeescript-templates)
            * [Stylus Templates](#stylus-templates)
            * [Yajl Templates](#yajl-templates)
            * [WLang Templates](#wlang-templates)
        * [Auf Variablen in Templates zugreifen](#auf-variablen-in-templates-zugreifen)
        * [Templates mit `yield` und verschachtelte Layouts](#templates-mit-yield-und-verschachtelte-layouts)
        * [Inline-Templates](#inline-templates)
        * [Benannte Templates](#benannte-templates)
        * [Dateiendungen zuordnen](#dateiendungen-zuordnen)
        * [Eine eigene Template-Engine hinzufügen](#eine-eigene-template-engine-hinzufgen)
        * [Eigene Methoden zum Aufsuchen von Templates verwenden](#eigene-methoden-zum-aufsuchen-von-templates-verwenden)
    * [Filter](#filter)
    * [Helfer](#helfer)
        * [Sessions verwenden](#sessions-verwenden)
        * [Anhalten](#anhalten)
        * [Weiterspringen](#weiterspringen)
        * [Eine andere Route ansteuern](#eine-andere-route-ansteuern)
        * [Body, Status-Code und Header setzen](#body-status-code-und-header-setzen)
        * [Response-Streams](#response-streams)
        * [Logger](#logger)
        * [Mime-Types](#mime-types)
        * [URLs generieren](#urls-generieren)
        * [Browser-Umleitung](#browser-umleitung)
        * [Cache einsetzen](#cache-einsetzen)
        * [Dateien versenden](#dateien-versenden)
        * [Das Request-Objekt](#das-request-objekt)
        * [Anhänge](#anhnge)
        * [Umgang mit Datum und Zeit](#umgang-mit-datum-und-zeit)
        * [Nachschlagen von Template-Dateien](#nachschlagen-von-template-dateien)
        * [Konfiguration](#konfiguration)
            * [Einstellung des Angriffsschutzes](#einstellung-des-angriffsschutzes)
            * [Mögliche Einstellungen](#mgliche-einstellungen)
    * [Umgebungen](#umgebungen)
    * [Fehlerbehandlung](#fehlerbehandlung)
        * [Nicht gefunden](#nicht-gefunden)
        * [Fehler](#fehler)
    * [Rack-Middleware](#rack-middleware)
    * [Testen](#testen)
    * [Sinatra::Base - Middleware, Bibliotheken und modulare Anwendungen](#sinatrabase---middleware-bibliotheken-und-modulare-anwendungen)
        * [Modularer vs. klassischer Stil](#modularer-vs-klassischer-stil)
        * [Eine modulare Applikation bereitstellen](#eine-modulare-applikation-bereitstellen)
        * [Eine klassische Anwendung mit einer config.ru verwenden](#eine-klassische-anwendung-mit-einer-configru-verwenden)
        * [Wann sollte eine config.ru-Datei verwendet werden?](#wann-sollte-eine-configru-datei-verwendet-werden)
        * [Sinatra als Middleware nutzen](#sinatra-als-middleware-nutzen)
        * [Dynamische Applikationserstellung](#dynamische-applikationserstellung)
    * [Geltungsbereich und Bindung](#geltungsbereich-und-bindung)
        * [Anwendungs- oder Klassen-Scope](#anwendungs--oder-klassen-scope)
        * [Anfrage- oder Instanz-Scope](#anfrage--oder-instanz-scope)
        * [Delegation-Scope](#delegation-scope)
    * [Kommandozeile](#kommandozeile)
      * [Multi-Threading](#multi-threading)
    * [Systemanforderungen](#systemanforderungen)
    * [Der neuste Stand (The Bleeding Edge)](#der-neuste-stand-the-bleeding-edge)
        * [Mit Bundler](#mit-bundler)
        * [Eigenes Repository](#eigenes-repository)
        * [Gem erstellen](#gem-erstellen)
    * [Versions-Verfahren](#versions-verfahren)
    * [Mehr](#mehr)

## Routen

In Sinatra wird eine Route durch eine HTTP-Methode und ein URL-Muster definiert.
Jeder dieser Routen wird ein Ruby-Block zugeordnet:

```ruby
get '/' do
  .. zeige etwas ..
end

post '/' do
  .. erstelle etwas ..
end

put '/' do
  .. update etwas ..
end

delete '/' do
  .. entferne etwas ..
end

options '/' do
  .. zeige, was wir können ..
end

link '/' do
  .. verbinde etwas ..
end

unlink '/' do
  .. trenne etwas ..
end
```

Die Routen werden in der Reihenfolge durchlaufen, in der sie definiert wurden.
Das erste Routen-Muster, das mit dem Request übereinstimmt, wird ausgeführt.

Die Muster der Routen können benannte Parameter beinhalten, die über den
`params`-Hash zugänglich gemacht werden:

```ruby
get '/hallo/:name' do
  # passt auf "GET /hallo/foo" und "GET /hallo/bar"
  # params['name'] ist dann 'foo' oder 'bar'
  "Hallo #{params['name']}!"
end
```

Man kann auf diese auch mit Block-Parametern zugreifen:

```ruby
get '/hallo/:name' do |n|
  # n entspricht hier params['name']
  "Hallo #{n}!"
end
```

Routen-Muster können auch mit sog. Splat- oder Wildcard-Parametern über das
`params['splat']`-Array angesprochen werden:

```ruby
get '/sag/*/zu/*' do
  # passt z.B. auf /sag/hallo/zu/welt
  params['splat'] # => ["hallo", "welt"]
end

get '/download/*.*' do
  # passt auf /download/pfad/zu/datei.xml
  params['splat'] # => ["pfad/zu/datei", "xml"]
end
```

Oder mit Block-Parametern:

```ruby
get '/download/*.*' do |pfad, endung|
  [pfad, endung] # => ["Pfad/zu/Datei", "xml"]
end
```

Routen mit regulären Ausdrücken sind auch möglich:

```ruby
get /\A\/hallo\/([\w]+)\z/ do
  "Hallo, #{params['captures'].first}!"
end
```

Und auch hier können Block-Parameter genutzt werden:

```ruby
get %r{/hallo/([\w]+)} do |c|
  "Hallo, #{c}!"
end
```

Routen-Muster können auch mit optionalen Parametern ausgestattet werden:

```ruby
get '/posts/:format?' do
  # passt auf "GET /posts/" sowie jegliche Erweiterung
  # wie "GET /posts/json", "GET /posts/xml" etc.
end
```

Routen können auch den query-Parameter verwenden:

```ruby
get '/posts' do
  # matches "GET /posts?title=foo&author=bar"
  title = params['title']
  author = params['author']
  # uses title and author variables; query is optional to the /posts route
end
```

Anmerkung: Solange man den sog. Path Traversal Attack-Schutz nicht deaktiviert
(siehe weiter unten), kann es sein, dass der Request-Pfad noch vor dem
Abgleich mit den Routen modifiziert wird.

### Bedingungen

An Routen können eine Vielzahl von Bedingungen geknüpft werden, die erfüllt
sein müssen, damit der Block ausgeführt wird. Möglich wäre etwa eine
Einschränkung des User-Agents über die interne Bedingung `:agent`:

```ruby
get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
  "Du verwendest Songbird Version #{params['agent'][0]}"
end
```

Wird Songbird als Browser nicht verwendet, springt Sinatra zur nächsten Route:

```ruby
get '/foo' do
  # passt auf andere Browser
end
```

Andere mitgelieferte Bedingungen sind `:host_name` und `:provides`:

```ruby
get '/', :host_name => /^admin\./ do
  "Adminbereich, Zugriff verweigert!"
end

get '/', :provides => 'html' do
  haml :index
end

get '/', :provides => ['rss', 'atom', 'xml'] do
  builder :feed
end
```
`provides` durchsucht den Accept-Header der Anfrage

Eigene Bedingungen können relativ einfach hinzugefügt werden:

```ruby
set(:wahrscheinlichkeit) { |value| condition { rand <= value } }

get '/auto_gewinnen', :wahrscheinlichkeit => 0.1 do
  "Du hast gewonnen!"
end

get '/auto_gewinnen' do
  "Tut mir leid, verloren."
end
```

Bei Bedingungen, die mehrere Werte annehmen können, sollte ein Splat verwendet
werden:

```ruby
set(:auth) do |*roles|   # <- hier kommt der Splat ins Spiel
  condition do
    unless logged_in? && roles.any? {|role| current_user.in_role? role }
      redirect "/login/", 303
    end
  end
end

get "/mein/account/", :auth => [:user, :admin] do
  "Mein Account"
end

get "/nur/admin/", :auth => :admin do
  "Nur Admins dürfen hier rein!"
end
```

### Rückgabewerte

Durch den Rückgabewert eines Routen-Blocks wird mindestens der Response-Body
festgelegt, der an den HTTP-Client, bzw. die nächste Rack-Middleware,
weitergegeben wird. Im Normalfall handelt es sich hierbei, wie in den
vorangehenden Beispielen zu sehen war, um einen String. Es werden allerdings
auch andere Werte akzeptiert.

Es kann jedes gültige Objekt zurückgegeben werden, bei dem es sich entweder um
einen Rack-Rückgabewert, einen Rack-Body oder einen HTTP-Status-Code handelt:

*   Ein Array mit drei Elementen: `[Status (Fixnum), Headers (Hash),
    Response-Body (antwortet auf #each)]`.
*   Ein Array mit zwei Elementen: `[Status (Fixnum), Response-Body (antwortet
    auf #each)]`.
*   Ein Objekt, das auf `#each` antwortet und den an diese Methode übergebenen
    Block nur mit Strings als Übergabewerte aufruft.
*   Ein Fixnum, das den Status-Code festlegt.

Damit lässt sich relativ einfach Streaming implementieren:

```ruby
class Stream
  def each
    100.times { |i| yield "#{i}\n" }
  end
end

get('/') { Stream.new }
```

Ebenso kann die `stream`-Helfer-Methode (s.u.) verwendet werden, die Streaming
direkt in die Route integriert.

### Eigene Routen-Muster

Wie oben schon beschrieben, ist Sinatra von Haus aus mit Unterstützung für
String-Muster und Reguläre Ausdrücke zum Abgleichen von Routen ausgestattet.
Das muss aber noch nicht alles sein, es können ohne großen Aufwand eigene
Routen-Muster erstellt werden:

```ruby
class AllButPattern
  Match = Struct.new(:captures)

  def initialize(except)
    @except   = except
    @captures = Match.new([])
  end

  def match(str)
    @captures unless @except === str
  end
end

def all_but(pattern)
  AllButPattern.new(pattern)
end

get all_but("/index") do
  # ...
end
```

Beachte, dass das obige Beispiel etwas übertrieben wirkt. Es geht auch einfacher:

```ruby
get // do
  pass if request.path_info == "/index"
  # ...
end
```

Oder unter Verwendung eines negativen look ahead:

```ruby
get %r{^(?!/index$)} do
  # ...
end
```

## Statische Dateien

Statische Dateien werden im `./public`-Ordner erwartet. Es ist möglich,
einen anderen Ort zu definieren, indem man die `:public_folder`-Option setzt:

```ruby
set :public_folder, File.dirname(__FILE__) + '/static'
```

Zu beachten ist, dass der Ordnername `public` nicht Teil der URL ist. Die Datei
`./public/css/style.css` ist unter `http://example.com/css/style.css` zu finden.

Um den `Cache-Control`-Header mit Informationen zu versorgen, verwendet man
die `:static_cache_control`-Einstellung (s.u.).

## Views/Templates

Alle Templatesprachen verwenden ihre eigene Renderingmethode, die jeweils
einen String zurückgibt:

```ruby
get '/' do
  erb :index
end
```

Dieses Beispiel rendert `views/index.erb`.

Anstelle eines Templatenamens kann man auch direkt die Templatesprache verwenden:

```ruby
get '/' do
  code = "<%= Time.now %>"
  erb code
end
```

Templates nehmen ein zweite Argument an, den Options-Hash:

```ruby
get '/' do
  erb :index, :layout => :post
end
```

Dieses Beispiel rendert `views/index.erb` eingebettet in `views/post.erb`
(Voreinstellung ist `views/layout.erb`, sofern es vorhanden ist.)

Optionen, die Sinatra nicht versteht, werden an das Template weitergereicht:

```ruby
get '/' do
  haml :index, :format => :html5
end
```

Für alle Templates können auch Einstellungen, die für alle Routen gelten,
festgelegt werden:

```ruby
set :haml, :format => :html5

get '/' do
  haml :index
end
```

Optionen, die an die Rendermethode weitergegeben werden, überschreiben die
Einstellungen, die mit `set` festgelegt wurden.

Einstellungen:

<dl>
  <dt>locals</dt>
  <dd>Liste von lokalen Variablen, die an das Dokument weitergegeben werden.
    Praktisch für Partials:

    <tt>erb "<%= foo %>", :locals => {:foo => "bar"}</tt></dd>

  <dt>default_encoding</dt>
  <dd>Gibt die Stringkodierung an, die verwendet werden soll. Voreingestellt
    auf <tt>settings.default_encoding</tt>.</dd>

  <dt>views</dt>
  <dd>Ordner, aus dem die Templates geladen werden. Voreingestellt auf
    <tt>settings.views</tt>.</dd>

  <dt>layout</dt>
  <dd>Legt fest, ob ein Layouttemplate verwendet werden soll oder nicht
    (<tt>true</tt> oder<tt>false</tt>). Ist es ein Symbol, dann legt es fest,
    welches Template als Layout verwendet wird:

    <tt>erb :index, :layout => !request.xhr?</tt></dd>

  <dt>content_type</dt>
  <dd>Content-Typ den das Template ausgibt. Voreinstellung hängt von der
    Templatesprache ab.</dd>

  <dt>scope</dt>
  <dd>Scope, in dem das Template gerendert wird. Liegt standardmäßig innerhalb
    der App-Instanz. Wird Scope geändert, sind Instanzvariablen und
    Helfermethoden nicht verfügbar.</dd>

  <dt>layout_engine</dt>
  <dd>Legt fest, welcher Renderer für das Layout verantwortlich ist. Hilfreich
    für Sprachen, die sonst keine Templates unterstützen. Voreingestellt auf
    den Renderer, der für das Template verwendet wird:

    <tt>set :rdoc, :layout_engine => :erb</tt></dd>

  <dt>layout_options</dt>
  <dd>Besondere Einstellungen, die nur für das Rendering verwendet werden:

    <tt>set :rdoc, :layout_options => { :views => 'views/layouts' }</tt></dd>
</dl>

Sinatra geht davon aus, dass die Templates sich im `./views` Verzeichnis
befinden. Es kann jedoch ein anderer Ordner festgelegt werden:

```ruby
set :views, settings.root + '/templates'
```

Es ist zu beachten, dass immer mit Symbolen auf Templates verwiesen werden muss,
auch dann, wenn sie sich in einem Unterordner befinden:

```ruby
haml :'unterverzeichnis/template'
```

Rendering-Methoden rendern jeden String direkt.

### Direkte Templates

```ruby
get '/' do
  haml '%div.title Hallo Welt'
end
```

Hier wird der String direkt gerendert.

### Verfügbare Templatesprachen

Einige Sprachen haben mehrere Implementierungen. Um festzulegen, welche
verwendet wird (und dann auch Thread-sicher ist), verwendet man am besten zu
Beginn ein `'require'`:

```ruby
require 'rdiscount' # oder require 'bluecloth'
get('/') { markdown :index }
```

#### Haml Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://haml.info/">haml</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.haml</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>haml :index, :format => :html5</tt></td>
  </tr>
</table>


#### Erb Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://www.kuwata-lab.com/erubis/">erubis</a> oder erb
    (Standardbibliothek von Ruby)</td>
  </tr>
  <tr>
    <td>Dateierweiterungen</td>
    <td><tt>.erb</tt>, <tt>.rhtml</tt> oder <tt>.erubis</tt> (nur Erubis)</td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>erb :index</tt></td>
  </tr>
</table>


#### Builder Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/jimweirich/builder">builder</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.builder</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>builder { |xml| xml.em "Hallo" }</tt></td>
  </tr>
</table>

Nimmt ebenso einen Block für Inline-Templates entgegen (siehe Beispiel).

#### Nokogiri Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://www.nokogiri.org/">nokogiri</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.nokogiri</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>nokogiri { |xml| xml.em "Hallo" }</tt></td>
  </tr>
</table>

Nimmt ebenso einen Block für Inline-Templates entgegen (siehe Beispiel).

#### Sass Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://sass-lang.com/">sass</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.sass</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>sass :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>


#### SCSS Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://sass-lang.com/">sass</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.scss</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>scss :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>


#### Less Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://lesscss.org/">less</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.less</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>less :stylesheet</tt></td>
  </tr>
</table>


#### Liquid Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://liquidmarkup.org/">liquid</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.liquid</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>liquid :index, :locals => { :key => 'Wert' }</tt></td>
  </tr>
</table>

Da man aus dem Liquid-Template heraus keine Ruby-Methoden aufrufen kann
(ausgenommen `yield`), wird man üblicherweise locals verwenden wollen, mit
denen man Variablen weitergibt.

#### Markdown Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td>Eine der folgenden Bibliotheken:
        <a href="https://github.com/davidfstr/rdiscount" title="RDiscount">RDiscount</a>,
        <a href="https://github.com/vmg/redcarpet" title="RedCarpet">RedCarpet</a>,
        <a href="http://deveiate.org/projects/BlueCloth" title="BlueCloth">BlueCloth</a>,
        <a href="http://kramdown.gettalong.org/" title="kramdown">kramdown</a> oder
        <a href="https://github.com/bhollis/maruku" title="maruku">maruku</a>
    </td>
  </tr>
  <tr>
    <td>Dateierweiterungen</td>
    <td><tt>.markdown</tt>, <tt>.mkd</tt> und <tt>.md</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>markdown :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

Da man aus den Markdown-Templates heraus keine Ruby-Methoden aufrufen und auch
keine locals verwenden kann, wird man Markdown üblicherweise in Kombination
mit anderen Renderern verwenden wollen:

```ruby
erb :overview, :locals => { :text => markdown(:einfuehrung) }
```

Beachte, dass man die `markdown`-Methode auch aus anderen Templates heraus
aufrufen kann:

```ruby
%h1 Gruß von Haml!
%p= markdown(:Grüße)
```

Da man Ruby nicht von Markdown heraus aufrufen kann, können auch Layouts nicht
in Markdown geschrieben werden. Es ist aber möglich, einen Renderer für die
Templates zu verwenden und einen anderen für das Layout, indem die
`:layout_engine`-Option verwendet wird.

#### Textile Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://redcloth.org/">RedCloth</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.textile</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>textile :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

Da man aus dem Textile-Template heraus keine Ruby-Methoden aufrufen und auch
keine locals verwenden kann, wird man Textile üblicherweise in Kombination mit
anderen Renderern verwenden wollen:

```ruby
erb :overview, :locals => { :text => textile(:einfuehrung) }
```

Beachte, dass man die `textile`-Methode auch aus anderen Templates heraus
aufrufen kann:

```ruby
%h1 Gruß von Haml!
%p= textile(:Grüße)
```

Da man Ruby nicht von Textile heraus aufrufen kann, können auch Layouts nicht
in Textile geschrieben werden. Es ist aber möglich, einen Renderer für die
Templates zu verwenden und einen anderen für das Layout, indem die
`:layout_engine`-Option verwendet wird.

#### RDoc Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://rdoc.sourceforge.net/">rdoc</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.rdoc</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>textile :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

Da man aus dem RDoc-Template heraus keine Ruby-Methoden aufrufen und auch
keine locals verwenden kann, wird man RDoc üblicherweise in Kombination mit
anderen Renderern verwenden wollen:

```ruby
erb :overview, :locals => { :text => rdoc(:einfuehrung) }
```

Beachte, dass man die `rdoc`-Methode auch aus anderen Templates heraus
aufrufen kann:

```ruby
%h1 Gruß von Haml!
%p= rdoc(:Grüße)
```

Da man Ruby nicht von RDoc heraus aufrufen kann, können auch Layouts nicht in
RDoc geschrieben werden. Es ist aber möglich, einen Renderer für die Templates
zu verwenden und einen anderen für das Layout, indem die
`:layout_engine`-Option verwendet wird.

#### AsciiDoc Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://asciidoctor.org/" title="Asciidoctor">Asciidoctor</a></td>
  </tr>
  <tr>
    <td>Dateierweiterungen</td>
    <td><tt>.asciidoc</tt>, <tt>.adoc</tt> und <tt>.ad</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>asciidoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

Da man aus dem AsciiDoc-Template heraus keine Ruby-Methoden aufrufen kann
(ausgenommen `yield`), wird man üblicherweise locals verwenden wollen, mit
denen man Variablen weitergibt.

#### Radius Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/jlong/radius">radius</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.radius</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>radius :index, :locals => { :key => 'Wert' }</tt></td>
  </tr>
</table>

Da man aus dem Radius-Template heraus keine Ruby-Methoden aufrufen kann, wird
man üblicherweise locals verwenden wollen, mit denen man Variablen weitergibt.

#### Markaby Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://markaby.github.io/">markaby</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.mab</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>markaby { h1 "Willkommen!" }</tt></td>
  </tr>
</table>

Nimmt ebenso einen Block für Inline-Templates entgegen (siehe Beispiel).

#### RABL Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/nesquena/rabl">rabl</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.rabl</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>rabl :index</tt></td>
  </tr>
</table>

#### Slim Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="http://slim-lang.com/">slim</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.slim</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>slim :index</tt></td>
  </tr>
</table>

#### Creole Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/minad/creole">creole</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.creole</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>creole :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

Da man aus dem Creole-Template heraus keine Ruby-Methoden aufrufen und auch
keine locals verwenden kann, wird man Creole üblicherweise in Kombination mit
anderen Renderern verwenden wollen:

```ruby
erb :overview, :locals => { :text => creole(:einfuehrung) }
```

Beachte, dass man die `creole`-Methode auch aus anderen Templates heraus
aufrufen kann:

```ruby
%h1 Gruß von Haml!
%p= creole(:Grüße)
```

Da man Ruby nicht von Creole heraus aufrufen kann, können auch Layouts nicht in
Creole geschrieben werden. Es ist aber möglich, einen Renderer für die Templates
zu verwenden und einen anderen für das Layout, indem die `:layout_engine`-Option
verwendet wird.

#### MediaWiki Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/nricciar/wikicloth" title="WikiCloth">WikiCloth</a></td>
  </tr>
  <tr>
    <td>Dateierweiterungen</td>
    <td><tt>.mediawiki</tt> und <tt>.mw</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>mediawiki :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

Da man aus dem Mediawiki-Template heraus keine Ruby-Methoden aufrufen und auch
keine locals verwenden kann, wird man Mediawiki üblicherweise in Kombination mit
anderen Renderern verwenden wollen:

```ruby
erb :overview, :locals => { :text => mediawiki(:introduction) }
```

Beachte: Man kann die `mediawiki`-Methode auch aus anderen Templates
heraus aufrufen:

```ruby
%h1 Grüße von Haml!
%p= mediawiki(:greetings)
```

Da man Ruby nicht von MediaWiki heraus aufrufen kann, können auch Layouts nicht
in MediaWiki geschrieben werden. Es ist aber möglich, einen Renderer für die
Templates zu verwenden und einen anderen für das Layout, indem die
`:layout_engine`-Option verwendet wird.

#### CoffeeScript Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/josh/ruby-coffee-script">coffee-script</a>
        und eine <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme">Möglichkeit JavaScript auszuführen</a>.
    </td>
  </tr>
    <td>Dateierweiterung</td>
    <td><tt>.coffee</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>coffee :index</tt></td>
  </tr>
</table>

#### Stylus Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td>
      <a href="https://github.com/forgecrafted/ruby-stylus" title="Ruby Stylus">
        Stylus
      </a> und eine Möglichkeit
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        JavaScript auszuführen
      </a>.
    </td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.styl</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>stylus :index</tt></td>
  </tr>
</table>

Um Stylus-Templates ausführen zu können, müssen `stylus` und `stylus/tilt`
zuerst geladen werden:

```ruby
require 'sinatra'
require 'stylus'
require 'stylus/tilt'

get '/' do
  stylus :example
end
```

#### Yajl Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/brianmario/yajl-ruby" title="yajl-ruby">yajl-ruby</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.yajl</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td>
      <tt>
        yajl :index,
             :locals => { :key => 'qux' },
             :callback => 'present',
             :variable => 'resource'
      </tt>
    </td>
  </tr>
</table>

Die Template-Quelle wird als Ruby-String evaluiert. Die daraus resultierende
json Variable wird mit Hilfe von `#to_json` umgewandelt:

```ruby
json = { :foo => 'bar' }
json[:baz] = key
```

Die `:callback` und `:variable` Optionen können mit dem gerenderten Objekt
verwendet werden:

```javascript
var resource = {"foo":"bar","baz":"qux"};
present(resource);
```

#### WLang Templates

<table>
  <tr>
    <td>Abhängigkeit</td>
    <td><a href="https://github.com/blambeau/wlang/">wlang</a></td>
  </tr>
  <tr>
    <td>Dateierweiterung</td>
    <td><tt>.wlang</tt></td>
  </tr>
  <tr>
    <td>Beispiel</td>
    <td><tt>wlang :index, :locals => { :key => 'value' }</tt></td>
  </tr>
</table>

Ruby-Methoden in Wlang aufzurufen entspricht nicht den idiomatischen Vorgaben
von Wlang, es bietet sich deshalb an, `:locals` zu verwenden. Layouts, die
Wlang und `yield` verwenden, werden aber trotzdem unterstützt.

Rendert den eingebetteten Template-String.

### Auf Variablen in Templates zugreifen

Templates werden in demselben Kontext ausgeführt wie Routen. Instanzvariablen
in Routen sind auch direkt im Template verfügbar:

```ruby
get '/:id' do
  @foo = Foo.find(params['id'])
  haml '%h1= @foo.name'
end
```

Oder durch einen expliziten Hash von lokalen Variablen:

```ruby
get '/:id' do
  foo = Foo.find(params['id'])
  haml '%h1= bar.name', :locals => { :bar => foo }
end
```

Dies wird typischerweise bei Verwendung von Subtemplates (partials) in anderen
Templates eingesetzt.

### Templates mit `yield` und verschachtelte Layouts

Ein Layout ist üblicherweise ein Template, das ein `yield` aufruft. Ein solches
Template kann entweder wie oben beschrieben über die `:template` Option
verwendet werden oder mit einem Block gerendert werden:

```ruby
erb :post, :layout => false do
  erb :index
end
```

Dieser Code entspricht weitestgehend `erb :index, :layout => :post`.

Blöcke an Render-Methoden weiterzugeben ist besonders bei verschachtelten
Layouts hilfreich:

```ruby
erb :main_layout, :layout => false do
  erb :admin_layout do
    erb :user
  end
end
```

Der gleiche Effekt kann auch mit weniger Code erreicht werden:

```ruby
erb :admin_layout, :layout => :main_layout do
  erb :user
end
```

Zur Zeit nehmen folgende Renderer Blöcke an: `erb`, `haml`, `liquid`, `slim `
und `wlang`.

Das gleich gilt auch für die allgemeine `render` Methode.

### Inline-Templates

Templates können auch am Ende der Datei definiert werden:

```ruby
require 'sinatra'

get '/' do
  haml :index
end

__END__

@@ layout
%html
  = yield

@@ index
%div.title Hallo Welt!!!!!
```

Anmerkung: Inline-Templates, die in der Datei definiert sind, die `require
'sinatra'` aufruft, werden automatisch geladen. Um andere Inline-Templates in
anderen Dateien aufzurufen, muss explizit `enable :inline_templates` verwendet
werden.

### Benannte Templates

Templates können auch mit der Top-Level `template`-Methode definiert werden:

```ruby
template :layout do
  "%html\n  =yield\n"
end

template :index do
  '%div.title Hallo Welt!'
end

get '/' do
  haml :index
end
```

Wenn ein Template mit dem Namen "layout" existiert, wird es bei jedem Aufruf
verwendet. Durch `:layout => false` kann das Ausführen verhindert werden:

```ruby
get '/' do
  haml :index, :layout => !request.xhr?
  # !request.xhr? prüft, ob es sich um einen asynchronen Request handelt.
  # wenn nicht, dann verwende ein Layout (negiert durch !)
end
```

### Dateiendungen zuordnen

Um eine Dateiendung einer Template-Engine zuzuordnen, kann `Tilt.register`
genutzt werden. Wenn etwa die Dateiendung `tt` für Textile-Templates genutzt
werden soll, lässt sich dies wie folgt bewerkstelligen:

```ruby
Tilt.register :tt, Tilt[:textile]
```

### Eine eigene Template-Engine hinzufügen

Zu allererst muss die Engine bei Tilt registriert und danach eine
Rendering-Methode erstellt werden:

```ruby
Tilt.register :mtt, MeineTolleTemplateEngine

helpers do
  def mtt(*args) render(:mtt, *args) end
end

get '/' do
  mtt :index
end
```

Dieser Code rendert `./views/application.mtt`. Siehe
[github.com/rtomayko/tilt](https://github.com/rtomayko/tilt), um mehr über
Tilt zu erfahren.

### Eigene Methoden zum Aufsuchen von Templates verwenden

Um einen eigenen Mechanismus zum Aufsuchen von Templates zu
implementieren, muss `#find_template` definiert werden:

```ruby
configure do
  set :views [ './views/a', './views/b' ]
end

def find_template(views, name, engine, &block)
  Array(views).each do |v|
    super(v, name, engine, &block)
  end
end
```

## Filter

Before-Filter werden vor jedem Request in demselben Kontext, wie danach die
Routen, ausgeführt. So können etwa Request und Antwort geändert werden.
Gesetzte Instanzvariablen in Filtern können in Routen und Templates verwendet
werden:

```ruby
before do
  @note = 'Hi!'
  request.path_info = '/foo/bar/baz'
end

get '/foo/*' do
  @note #=> 'Hi!'
  params['splat'] #=> 'bar/baz'
end
```

After-Filter werden nach jedem Request in demselben Kontext ausgeführt und
können ebenfalls Request und Antwort ändern. In Before-Filtern gesetzte
Instanzvariablen können in After-Filtern verwendet werden:

```ruby
after do
  puts response.status
end
```

Filter können optional auch mit einem Muster ausgestattet werden, das auf den
Request-Pfad passen muss, damit der Filter ausgeführt wird:

```ruby
before '/protected/*' do
  authenticate!
end

after '/create/:slug' do |slug|
  session[:last_slug] = slug
end
```

Ähnlich wie Routen können Filter auch mit weiteren Bedingungen eingeschränkt
werden:

```ruby
before :agent => /Songbird/ do
  # ...
end

after '/blog/*', :host_name => 'example.com' do
  # ...
end
```

## Helfer

Durch die Top-Level `helpers`-Methode werden sogenannte Helfer-Methoden
definiert, die in Routen und Templates verwendet werden können:

```ruby
helpers do
  def bar(name)
    "#{name}bar"
  end
end

get '/:name' do
  bar(params['name'])
end
```

### Sessions verwenden
Sessions werden verwendet, um Zustände zwischen den Requests zu speichern. Sind
sie aktiviert, kann ein Session-Hash je Benutzer-Session verwendet werden:

```ruby
enable :sessions

get '/' do
  "value = " << session[:value].inspect
end

get '/:value' do
  session[:value] = params['value']
end
```

Beachte, dass `enable :sessions` alle Daten in einem Cookie speichert. Unter
Umständen kann dies negative Effekte haben, z.B. verursachen viele Daten
höheren, teilweise überflüssigen Traffic. Um das zu vermeiden, kann eine Rack-
Session-Middleware verwendet werden. Dabei wird auf `enable :sessions`
verzichtet und die Middleware wie üblich im Programm eingebunden:

```ruby
use Rack::Session::Pool, :expire_after => 2592000

get '/' do
  "value = " << session[:value].inspect
end

get '/:value' do
  session[:value] = params['value']
end
```

Um die Sicherheit zu erhöhen, werden Cookies, die Session-Daten führen, mit
einem sogenannten Session-Secret signiert. Da sich dieses Geheimwort bei jedem
Neustart der Applikation automatisch ändert, ist es sinnvoll, ein eigenes zu
wählen, damit sich alle Instanzen der Applikation dasselbe Session-Secret
teilen:

```ruby
set :session_secret, 'super_geheimes_Gegeimnis'
```

Zur weiteren Konfiguration kann man einen Hash mit Optionen in den `sessions`
Einstellungen ablegen.

```ruby
set :sessions, :domain => 'foo.com'
```

Um eine Session mit anderen Apps und zwischen verschiedenen Subdomains
von foo.com zu teilen, wird ein *.* der Domain vorangestellt:

```ruby
set :sessions, :domain => '.foo,com'
```

### Anhalten

Zum sofortigen Stoppen eines Request in einem Filter oder einer Route:

```ruby
halt
```

Der Status kann beim Stoppen mit angegeben werden:

```ruby
halt 410
```

Oder auch den Response-Body:

```ruby
halt 'Hier steht der Body'
```

Oder beides:

```ruby
halt 401, 'verschwinde!'
```

Sogar mit Headern:

```ruby
halt 402, {'Content-Type' => 'text/plain'}, 'Rache'
```

Natürlich ist es auch möglich, ein Template mit `halt` zu verwenden:

```ruby
halt erb(:error)
```

### Weiterspringen

Eine Route kann mittels `pass` zu der nächsten passenden Route springen:

```ruby
get '/raten/:wer' do
  pass unless params['wer'] == 'Frank'
  'Du hast mich!'
end

get '/raten/*' do
  'Du hast mich nicht!'
end
```

Der Block wird sofort verlassen und es wird nach der nächsten treffenden Route
gesucht. Ein 404-Fehler wird zurückgegeben, wenn kein treffendes Routen-Muster
gefunden wird.

### Eine andere Route ansteuern

Wenn nicht zu einer anderen Route gesprungen werden soll, sondern nur das
Ergebnis einer anderen Route gefordert wird, kann `call` für einen internen
Request verwendet werden:

```ruby
get '/foo' do
  status, headers, body = call env.merge("PATH_INFO" => '/bar')
  [status, headers, body.map(&:upcase)]
end

get '/bar' do
  "bar"
end
```

Beachte, dass in dem oben angegeben Beispiel die Performance erheblich erhöht
werden kann, wenn `"bar"` in eine Helfer-Methode umgewandelt wird, auf die
`/foo` und `/bar` zugreifen können.

Wenn der Request innerhalb derselben Applikations-Instanz aufgerufen und keine
Kopie der Instanz erzeugt werden soll, kann `call!` anstelle von `call`
verwendet werden.

### Body, Status-Code und Header setzen

Es ist möglich und empfohlen, den Status-Code sowie den Response-Body mit einem
Returnwert in der Route zu setzen. In manchen Situationen kann es jedoch sein,
dass der Body an anderer Stelle während der Ausführung gesetzt werden soll.
Dafür kann man die Helfer-Methode `body` einsetzen. Ist sie gesetzt, kann sie zu
einem späteren Zeitpunkt aufgerufen werden:

```ruby
get '/foo' do
  body "bar"
end

after do
  puts body
end
```

Ebenso ist es möglich, einen Block an `body` weiterzureichen, der dann vom
Rack-Handler ausgeführt wird (lässt sich z.B. zur Umsetzung von Streaming
einsetzen, siehe auch "Rückgabewerte").

Vergleichbar mit `body` lassen sich auch Status-Code und Header setzen:

```ruby
get '/foo' do
  status 418
  headers \
    "Allow"   => "BREW, POST, GET, PROPFIND, WHEN",
    "Refresh" => "Refresh: 20; http://www.ietf.org/rfc/rfc2324.txt"
  halt "Ich bin ein Teekesselchen"
end
```

Genau wie bei `body` liest ein Aufrufen von `headers` oder `status` ohne
Argumente den aktuellen Wert aus.

### Response-Streams

In manchen Situationen sollen Daten bereits an den Client zurückgeschickt
werden, bevor ein vollständiger Response bereit steht. Manchmal will man die
Verbindung auch erst dann beenden und Daten so lange an den Client
zurückschicken, bis er die Verbindung abbricht. Für diese Fälle gibt es die
`stream`-Helfer-Methode, die es einem erspart eigene Lösungen zu schreiben:

```ruby
get '/' do
  stream do |out|
    out << "Das ist ja mal wieder fanta -\n"
    sleep 0.5
    out << " (bitte warten…) \n"
    sleep 1
    out << "- stisch!\n"
  end
end
```

Damit lassen sich Streaming-APIs realisieren, sog.
[Server Sent Events](https://w3c.github.io/eventsource/), die als Basis für
[WebSockets](https://en.wikipedia.org/wiki/WebSocket) dienen. Ebenso können sie
verwendet werden, um den Durchsatz zu erhöhen, wenn ein Teil der Daten von
langsamen Ressourcen abhängig ist.

Es ist zu beachten, dass das Verhalten beim Streaming, insbesondere die Anzahl
nebenläufiger Anfragen, stark davon abhängt, welcher Webserver für die
Applikation verwendet wird. Einige Server unterstützen
Streaming nicht oder nur teilweise. Sollte der Server Streaming nicht
unterstützen, wird ein vollständiger Response-Body zurückgeschickt, sobald der
an `stream` weitergegebene Block abgearbeitet ist. Mit Shotgun funktioniert
Streaming z.B. überhaupt nicht.

Ist der optionale Parameter `keep_open` aktiviert, wird beim gestreamten Objekt
`close` nicht aufgerufen und es ist einem überlassen dies an einem beliebigen
späteren Zeitpunkt nachholen. Die Funktion ist jedoch nur bei Event-gesteuerten
Serven wie Thin oder Rainbows möglich, andere Server werden trotzdem den Stream
beenden:

```ruby
# Durchgehende Anfrage (long polling)

set :server, :thin
connections = []

get '/subscribe' do
  # Client-Registrierung beim Server, damit Events mitgeteilt werden können
  stream(:keep_open) do |out|
    connections << out
    # tote Verbindungen entfernen
    connections.reject!(&:closed?)
  end
end

post '/:message' do
  connections.each do |out|
    # Den Client über eine neue Nachricht in Kenntnis setzen
    # notify client that a new message has arrived
    out << params['message'] << "\n"

    # Den Client zur erneuten Verbindung auffordern
    out.close
  end

  # Rückmeldung
  "Mitteiling erhalten"
end
```

### Logger

Im Geltungsbereich eines Request stellt die `logger` Helfer-Methode eine `Logger`
Instanz zur Verfügung:

```ruby
get '/' do
  logger.info "es passiert gerade etwas"
  # ...
end
```

Der Logger übernimmt dabei automatisch alle im Rack-Handler eingestellten
Log-Vorgaben. Ist Loggen ausgeschaltet, gibt die Methode ein Leerobjekt zurück.
In den Routen und Filtern muss man sich also nicht weiter darum kümmern.

Beachte, dass das Loggen standardmäßig nur für `Sinatra::Application`
voreingestellt ist. Wird über `Sinatra::Base` vererbt, muss es erst aktiviert
werden:

```ruby
class MyApp < Sinatra::Base
  configure :production, :development  do
    enable :logging
  end
end
```

Damit auch keine Middleware das Logging aktivieren kann, muss die `logging`
Einstellung auf `nil` gesetzt werden. Das heißt aber auch, dass `logger` in
diesem Fall `nil` zurückgeben wird. Üblicherweise wird das eingesetzt, wenn ein
eigener Logger eingerichtet werden soll. Sinatra wird dann verwenden, was in
`env['rack.logger']` eingetragen ist.

### Mime-Types

Wenn `send_file` oder statische Dateien verwendet werden, kann es vorkommen,
dass Sinatra den Mime-Typ nicht kennt. Registriert wird dieser mit `mime_type`
per Dateiendung:

```ruby
configure do
  mime_type :foo, 'text/foo'
end
```

Es kann aber auch der `content_type`-Helfer verwendet werden:

```ruby
get '/' do
  content_type :foo
  "foo foo foo"
end
```

### URLs generieren

Zum Generieren von URLs sollte die `url`-Helfer-Methode genutzen werden, so z.B.
beim Einsatz von Haml:

```ruby
%a{:href => url('/foo')} foo
```

Soweit vorhanden, wird Rücksicht auf Proxys und Rack-Router genommen.

Diese Methode ist ebenso über das Alias `to` zu erreichen (siehe Beispiel unten).

### Browser-Umleitung

Eine Browser-Umleitung kann mithilfe der `redirect`-Helfer-Methode erreicht
werden:

```ruby
get '/foo' do
  redirect to('/bar')
end
```

Weitere Parameter werden wie Argumente der `halt`-Methode behandelt:

```ruby
redirect to('/bar'), 303
redirect 'http://www.google.com/', 'Hier bist du falsch'
```

Ebenso leicht lässt sich ein Schritt zurück mit dem Alias `redirect back`
erreichen:

```ruby
get '/foo' do
  "<a href='/bar'>mach was</a>"
end

get '/bar' do
  mach_was
  redirect back
end
```

Um Argumente an ein Redirect weiterzugeben, können sie entweder dem Query
übergeben:

```ruby
redirect to('/bar?summe=42')
```

oder eine Session verwendet werden:

```ruby
enable :sessions

get '/foo' do
  session[:secret] = 'foo'
  redirect to('/bar')
end

get '/bar' do
  session[:secret]
end
```

### Cache einsetzen

Ein sinnvolles Einstellen von Header-Daten ist die Grundlage für ein
ordentliches HTTP-Caching.

Der Cache-Control-Header lässt sich ganz einfach einstellen:

```ruby
get '/' do
  cache_control :public
  "schon gecached!"
end
```

Profitipp: Caching im before-Filter aktivieren

```ruby
before do
  cache_control :public, :must_revalidate, :max_age => 60
end
```

Bei Verwendung der `expires`-Helfermethode zum Setzen des gleichnamigen Headers,
wird `Cache-Control` automatisch eigestellt:

```ruby
before do
  expires 500, :public, :must_revalidate
end
```

Um alles richtig zu machen, sollten auch `etag` oder `last_modified` verwendet
werden. Es wird empfohlen, dass diese Helfer aufgerufen werden **bevor** die
eigentliche Arbeit anfängt, da sie sofort eine Antwort senden, wenn der Client
eine aktuelle Version im Cache vorhält:

```ruby
get '/article/:id' do
  @article = Article.find params['id']
  last_modified @article.updated_at
  etag @article.sha1
  erb :article
end
```

ebenso ist es möglich einen
[schwachen ETag](https://de.wikipedia.org/wiki/HTTP_ETag) zu verwenden:

```ruby
etag @article.sha1, :weak
```

Diese Helfer führen nicht das eigentliche Caching aus, sondern geben die dafür
notwendigen Informationen an den Cache weiter. Für schnelle Reverse-Proxy
Cache-Lösungen bietet sich z.B.
[rack-cache](https://github.com/rtomayko/rack-cache) an:

```ruby
require "rack/cache"
require "sinatra"

use Rack::Cache

get '/' do
  cache_control :public, :max_age => 36000
  sleep 5
  "hello"
end
```

Um den `Cache-Control`-Header mit Informationen zu versorgen, verwendet man die
`:static_cache_control`-Einstellung (s.u.).

Nach RFC 2616 sollte sich die Anwendung anders verhalten, wenn ein If-Match oder
ein If-None_match Header auf `*` gesetzt wird in Abhängigkeit davon, ob die
Resource bereits existiert. Sinatra geht davon aus, dass Ressourcen bei sicheren
Anfragen (z.B. bei get oder Idempotenten Anfragen wie put) bereits existieren,
wobei anderen Ressourcen (besipielsweise bei post), als neue Ressourcen
behandelt werden. Dieses Verhalten lässt sich mit der `:new_resource` Option
ändern:

```ruby
get '/create' do
  etag '', :new_resource => true
  Article.create
  erb :new_article
end
```

Soll das schwache ETag trotzdem verwendet werden, verwendet man die `:kind`
Option:

```ruby
etag '', :new_resource => true, :kind => :weak
```

### Dateien versenden

Um den Inhalt einer Datei als Response zurückzugeben, kann die
`send_file`-Helfer-Methode verwendet werden:

```ruby
get '/' do
  send_file 'foo.png'
end
```

Für `send_file` stehen einige Hash-Optionen zur Verfügung:

```ruby
send_file 'foo.png', :type => :jpg
```

<dl>
  <dt>filename</dt>
  <dd>Dateiname als Response. Standardwert ist der eigentliche Dateiname.</dd>

  <dt>last_modified</dt>
  <dd>Wert für den Last-Modified-Header, Standardwert ist <tt>mtime</tt> der
    Datei.</dd>

  <dt>type</dt>
  <dd>Content-Type, der verwendet werden soll. Wird, wenn nicht angegeben, von
    der Dateiendung abgeleitet.</dd>

  <dt>disposition</dt>
  <dd>Verwendet für Content-Disposition. Mögliche Werte sind: <tt>nil</tt>
    (Standard), <tt>:attachment</tt> und <tt>:inline</tt>.</dd>

  <dt>length</dt>
  <dd>Content-Length-Header. Standardwert ist die Dateigröße.</dd>
</dl>

Soweit vom Rack-Handler unterstützt, werden neben der Übertragung über den
Ruby-Prozess auch andere Möglichkeiten genutzt. Bei Verwendung der
`send_file`-Helfer-Methode kümmert sich Sinatra selbstständig um die
Range-Requests.

### Das Request-Objekt

Auf das `request`-Objekt der eigehenden Anfrage kann vom Anfrage-Scope aus
zugegriffen werden:

```ruby
# App läuft unter http://example.com/example
get '/foo' do
  t = %w[text/css text/html application/javascript]
  request.accept              # ['text/html', '*/*']
  request.accept? 'text/xml'  # true
  request.preferred_type(t)   # 'text/html'
  request.body                # Request-Body des Client (siehe unten)
  request.scheme              # "http"
  request.script_name         # "/example"
  request.path_info           # "/foo"
  request.port                # 80
  request.request_method      # "GET"
  request.query_string        # ""
  request.content_length      # Länge des request.body
  request.media_type          # Medientypus von request.body
  request.host                # "example.com"
  request.get?                # true (ähnliche Methoden für andere Verben)
  request.form_data?          # false
  request["irgendein_param"]  # Wert von einem Parameter; [] ist die Kurzform für den params Hash
  request.referrer            # Der Referrer des Clients oder '/'
  request.user_agent          # User-Agent (verwendet in der :agent Bedingung)
  request.cookies             # Hash des Browser-Cookies
  request.xhr?                # Ist das hier ein Ajax-Request?
  request.url                 # "http://example.com/example/foo"
  request.path                # "/example/foo"
  request.ip                  # IP-Adresse des Clients
  request.secure?             # false (true wenn SSL)
  request.forwarded?          # true (Wenn es hinter einem Reverse-Proxy verwendet wird)
  request.env                 # vollständiger env-Hash von Rack übergeben
end
```

Manche Optionen, wie etwa `script_name` oder `path_info`, sind auch
schreibbar:

```ruby
before { request.path_info = "/" }

get "/" do
  "Alle Anfragen kommen hier an!"
end
```

Der `request.body` ist ein IO- oder StringIO-Objekt:

```ruby
post "/api" do
  request.body.rewind # falls schon jemand davon gelesen hat
  daten = JSON.parse request.body.read
  "Hallo #{daten['name']}!"
end
```

### Anhänge

Damit der Browser erkennt, dass ein Response gespeichert und nicht im Browser
angezeigt werden soll, kann der `attachment`-Helfer verwendet werden:

```ruby
get '/' do
  attachment
  "Speichern!"
end
```

Ebenso kann eine Dateiname als Parameter hinzugefügt werden:

```ruby
get '/' do
  attachment "info.txt"
  "Speichern!"
end
```

### Umgang mit Datum und Zeit

Sinatra bietet eine `time_for`-Helfer-Methode, die aus einem gegebenen Wert ein
Time-Objekt generiert. Ebenso kann sie nach `DateTime`, `Date` und ähnliche
Klassen konvertieren:

```ruby
get '/' do
  pass if Time.now > time_for('Dec 23, 2012')
  "noch Zeit"
end
```

Diese Methode wird intern für +expires, `last_modiefied` und ihresgleichen
verwendet. Mit ein paar Handgriffen lässt sich diese Methode also in ihrem
Verhalten erweitern, indem man `time_for` in der eigenen Applikation
überschreibt:

```ruby
helpers do
  def time_for(value)
    case value
    when :yesterday then Time.now - 24*60*60
    when :tomorrow  then Time.now + 24*60*60
    else super
    end
  end
end

get '/' do
  last_modified :yesterday
  expires :tomorrow
  "Hallo"
end
```

### Nachschlagen von Template-Dateien

Die `find_template`-Helfer-Methode wird genutzt, um Template-Dateien zum Rendern
aufzufinden:

```ruby
find_template settings.views, 'foo', Tilt[:haml] do |file|
  puts "könnte diese hier sein: #{file}"
end
```

Das ist zwar nicht wirklich brauchbar, aber wenn man sie überschreibt, kann sie
nützlich werden, um eigene Nachschlage-Mechanismen einzubauen. Zum Beispiel
dann, wenn mehr als nur ein view-Verzeichnis verwendet werden soll:

```ruby
set :views, ['views', 'templates']

helpers do
  def find_template(views, name, engine, &block)
    Array(views).each { |v| super(v, name, engine, &block) }
  end
end
```

Ein anderes Beispiel wäre, verschiedene Vereichnisse für verschiedene Engines
zu verwenden:

```ruby
set :views, :sass => 'views/sass', :haml => 'templates', :default => 'views'

helpers do
  def find_template(views, name, engine, &block)
    _, folder = views.detect { |k,v| engine == Tilt[k] }
    folder ||= views[:default]
    super(folder, name, engine, &block)
  end
end
```

Ebensogut könnte eine Extension aber auch geschrieben und mit anderen geteilt
werden!

Beachte, dass `find_template` nicht prüft, ob eine Datei tatsächlich existiert.
Es wird lediglich der angegebene Block aufgerufen und nach allen möglichen
Pfaden gesucht. Das ergibt kein Performance-Problem, da `render` `block`
verwendet, sobald eine Datei gefunden wurde. Ebenso werden Template-Pfade samt
Inhalt gecached, solange nicht im Entwicklungsmodus gearbeitet wird. Das sollte
im Hinterkopf behalten werden, wenn irgendwelche verrückten Methoden
zusammenbastelt werden.

### Konfiguration

Wird einmal beim Starten in jedweder Umgebung ausgeführt:

```ruby
configure do
  # setze eine Option
  set :option, 'wert'

  # setze mehrere Optionen
  set :a => 1, :b => 2

  # das gleiche wie `set :option, true`
  enable :option

  # das gleiche wie `set :option, false`
  disable :option

  # dynamische Einstellungen mit Blöcken
  set(:css_dir) { File.join(views, 'css') }
end
```

Läuft nur, wenn die Umgebung (RACK_ENV-Umgebungsvariable) auf `:production`
gesetzt ist:

```ruby
configure :production do
  ...
end
```

Läuft nur, wenn die Umgebung auf `:production` oder auf `:test` gesetzt ist:

```ruby
configure :production, :test do
  ...
end
```

Diese Einstellungen sind über `settings` erreichbar:

```ruby
configure do
  set :foo, 'bar'
end

get '/' do
  settings.foo? # => true
  settings.foo  # => 'bar'
  ...
end
```

#### Einstellung des Angriffsschutzes

Sinatra verwendet
[Rack::Protection](https://github.com/sinatra/rack-protection#readme), um die
Anwendung vor häufig vorkommenden Angriffen zu schützen. Diese Voreinstellung
lässt sich selbstverständlich deaktivieren, der damit verbundene
Geschwindigkeitszuwachs steht aber in keinem Verhätnis zu den möglichen
Risiken.

```ruby
disable :protection
```

Um einen bestimmten Schutzmechanismus zu deaktivieren, fügt man `protection`
einen Hash mit Optionen hinzu:

```ruby
set :protection, :except => :path_traversal
```

Neben Strings akzeptiert `:except` auch Arrays, um gleich mehrere
Schutzmechanismen zu deaktivieren:

```ruby
set :protection, :except => [:path_traversal, :session_hijacking]
```

#### Mögliche Einstellungen

<dl>
  <dt>absolute_redirects</dt>
  <dd>Wenn ausgeschaltet, wird Sinatra relative Redirects zulassen. Jedoch ist
  Sinatra dann nicht mehr mit RFC 2616 (HTTP 1.1) konform, das nur absolute
  Redirects zulässt. Sollte eingeschaltet werden, wenn die Applikation hinter
  einem Reverse-Proxy liegt, der nicht ordentlich eingerichtet ist. Beachte,
  dass die <tt>url</tt>-Helfer-Methode nach wie vor absolute URLs erstellen
  wird, es sei denn, es wird als zweiter Parameter <tt>false</tt> angegeben.
  Standardmäßig nicht aktiviert.</dd>

  <dt>add_charset</dt>
  <dd>Mime-Types werden hier automatisch der Helfer-Methode
  <tt>content_type</tt> zugeordnet. Es empfielt sich, Werte hinzuzufügen statt
  sie zu überschreiben: <tt>settings.add_charset << "application/foobar"</tt>
  </dd>

  <dt>app_file</dt>
  <dd>Pfad zur Hauptdatei der Applikation. Wird verwendet, um das Wurzel-,
  Inline-, View- und öffentliche Verzeichnis des Projekts festzustellen.</dd>

  <dt>bind</dt>
  <dd>IP-Address, an die gebunden wird (Standardwert: <tt>0.0.0.0</tt>
  <em>oder</em> <tt>localhost</tt>). Wird  nur für den eingebauten Server
  verwendet.</dd>

  <dt>default_encoding</dt>
  <dd>Das Encoding, falls keines angegeben wurde. Standardwert ist
  <tt>"utf-8"</tt>.</dd>

  <dt>dump_errors</dt>
  <dd>Fehler im Log anzeigen.</dd>

  <dt>environment</dt>
  <dd>Momentane Umgebung. Standardmäßig auf <tt>content_type</tt> oder
  <tt>"development"</tt> eingestellt, soweit ersteres nicht vorhanden.</dd>

  <dt>logging</dt>
  <dd>Den Logger verwenden.</dd>

  <dt>lock</dt>
  <dd>Jeder Request wird gelocked. Es kann nur ein Request pro Ruby-Prozess
  gleichzeitig verarbeitet werden. Eingeschaltet, wenn die Applikation
  threadsicher ist. Standardmäßig nicht aktiviert.</dd>

  <dt>method_override</dt>
  <dd>Verwende <tt>_method</tt>, um put/delete-Formulardaten in Browsern zu
  verwenden, die dies normalerweise nicht unterstützen.</dd>

  <dt>port</dt>
  <dd>Port für die Applikation. Wird nur im internen Server verwendet.</dd>

  <dt>prefixed_redirects</dt>
  <dd>Entscheidet, ob <tt>request.script_name</tt> in Redirects eingefügt wird
  oder nicht, wenn kein absoluter Pfad angegeben ist. Auf diese Weise verhält
  sich <tt>redirect '/foo'</tt> so, als wäre es ein <tt>redirect
  to('/foo')</tt>. Standardmäßig nicht aktiviert.</dd>

  <dt>protection</dt>
  <dd>Legt fest, ob der Schutzmechanismus für häufig Vorkommende Webangriffe
  auf Webapplikationen aktiviert wird oder nicht. Weitere Informationen im
  vorhergehenden Abschnitt.</dd>

  <dt>public_folder</dt>
  <dd>Das öffentliche Verzeichnis, aus dem Daten zur Verfügung gestellt werden
  können. Wird nur dann verwendet, wenn statische Daten zur Verfügung gestellt
  werden können (s.u. <tt>static</tt> Option). Leitet sich von der
  <tt>app_file</tt> Einstellung ab, wenn nicht gesetzt.</dd>

  <dt>public_dir</dt>
  <dd>Alias für <tt>public_folder</tt>, s.o.</dd>

  <dt>reload_templates</dt>
  <dd>Im development-Modus aktiviert.</dd>

  <dt>root</dt>
  <dd>Wurzelverzeichnis des Projekts. Leitet sich von der <tt>app_file</tt>
  Einstellung ab, wenn nicht gesetzt.</dd>

  <dt>raise_errors</dt>
  <dd>Einen Ausnahmezustand aufrufen. Beendet die Applikation. Ist automatisch
  aktiviert, wenn die Umgebung auf <tt>"test"</tt> eingestellt ist. Ansonsten
  ist diese Option deaktiviert.</dd>

  <dt>run</dt>
  <dd>Wenn aktiviert, wird Sinatra versuchen, den Webserver zu starten. Nicht
  verwenden, wenn Rackup oder anderes verwendet werden soll.</dd>

  <dt>running</dt>
  <dd>Läuft der eingebaute Server? Diese Einstellung nicht ändern!</dd>

  <dt>server</dt>
  <dd>Server oder Liste von Servern, die als eingebaute Server zur Verfügung
  stehen. Die Reihenfolge gibt die Priorität vor, die Voreinstellung hängt von
  der verwendenten Ruby Implementierung ab.</dd>

  <dt>sessions</dt>
  <dd>Sessions auf Cookiebasis mittels
  <tt>Rack::Session::Cookie</tt>aktivieren. Für weitere Infos bitte in der
  Sektion ‘Sessions verwenden’ nachschauen.</dd>

  <dt>show_exceptions</dt>
  <dd>Bei Fehlern einen Stacktrace im Browseranzeigen. Ist automatisch
  aktiviert, wenn die Umgebung auf <tt>"development"</tt> eingestellt ist.
  Ansonsten ist diese Option deaktiviert. Kann auch auf <tt>:after_handler</tt>
  gestellt werden, um eine anwendungsspezifische Fehlerbehandlung auszulösen,
  bevor der Fehlerverlauf im Browser angezeigt wird.</dd>

  <dt>static</dt>
  <dd>Entscheidet, ob Sinatra statische Dateien zur Verfügung stellen soll oder
  nicht. Sollte nicht aktiviert werden, wenn ein Server verwendet wird, der
  dies auch selbstständig erledigen kann. Deaktivieren wird die Performance
  erhöhen. Standardmäßig aktiviert.</dd>

  <dt>static_cache_control</dt>
  <dd>Wenn Sinatra statische Daten zur Verfügung stellt, können mit dieser
  Einstellung die <tt>Cache-Control</tt> Header zu den Responses hinzugefügt
  werden. Die Einstellung verwendet dazu die <tt>cache_control</tt>
  Helfer-Methode. Standardmäßig deaktiviert. Ein Array wird verwendet, um
  mehrere Werte gleichzeitig zu übergeben: <tt>set :static_cache_control,
  [:public, :max_age => 300]</tt></dd>

  <dt>threaded</dt>
  <dd>Wird es auf <tt>true</tt> gesetzt, wird Thin aufgefordert
  <tt>EventMachine.defer</tt> zur Verarbeitung des Requests einzusetzen.</dd>

  <dt>traps</dt>
  <dd>Einstellung, Sinatra System signalen umgehen soll.</dd>

  <dt>views</dt>
  <dd>Verzeichnis der Views. Leitet sich von der <tt>app_file</tt> Einstellung
  ab, wenn nicht gesetzt.</dd>

  <dt>x_cascade</dt>
  <dd>Einstellung, ob der X-Cascade Header bei fehlender Route gesetzt wird oder
  nicht. Standardeinstellung ist <tt>true</tt>.</dd>
</dl>

## Umgebungen

Es gibt drei voreingestellte Umgebungen in Sinatra: `"development"`,
`"production"` und `"test"`. Umgebungen können über die `RACK_ENV`
Umgebungsvariable gesetzt werden. Die Standardeinstellung ist `"development"`.
In diesem Modus werden alle Templates zwischen Requests neu geladen. Dazu gibt
es besondere Fehlerseiten für 404 Stati und Fehlermeldungen. In `"production"`
und `"test"` werden Templates automatisch gecached.

Um die Anwendung in einer anderen Umgebung auszuführen kann man die `-e`
Option verwenden:

```shell
ruby my_app.rb -e [ENVIRONMENT]
```

In der Anwendung kann man die die Methoden  `development?`, `test?` und
`production?` verwenden, um die aktuelle Umgebung zu erfahren.

## Fehlerbehandlung

Error-Handler laufen in demselben Kontext wie Routen und Filter, was bedeutet,
dass alle Goodies wie `haml`, `erb`, `halt`, etc. verwendet werden können.

### Nicht gefunden

Wenn eine `Sinatra::NotFound`-Exception geworfen wird oder der Statuscode 404
ist, wird der `not_found`-Handler ausgeführt:

```ruby
not_found do
  'Seite kann nirgendwo gefunden werden.'
end
```

### Fehler

Der `error`-Handler wird immer ausgeführt, wenn eine Exception in einem
Routen-Block oder in einem Filter geworfen wurde. In der
`development`-Umgebung wird es nur dann funktionieren, wenn die
`:show_exceptions`-Option auf `:after_handler` eingestellt wurde:

```ruby
set :show_exceptions, :after_handler
```

Die Exception kann über die `sinatra.error`-Rack-Variable angesprochen werden:

```ruby
error do
  'Entschuldige, es gab einen hässlichen Fehler - ' + env['sinatra.error'].message
end
```

Benutzerdefinierte Fehler:

```ruby
error MeinFehler do
  'Au weia, ' + env['sinatra.error'].message
end
```

Dann, wenn das passiert:

```ruby
get '/' do
  raise MeinFehler, 'etwas Schlimmes ist passiert'
end
```

bekommt man dieses:

```shell
Au weia, etwas Schlimmes ist passiert
```

Alternativ kann ein Error-Handler auch für einen Status-Code definiert werden:

```ruby
error 403 do
  'Zugriff verboten'
end

get '/geheim' do
  403
end
```

Oder ein Status-Code-Bereich:

```ruby
error 400..510 do
  'Hallo?'
end
```

Sinatra setzt verschiedene `not_found`- und `error`-Handler in der
Development-Umgebung ein, um hilfreiche Debugging Informationen und Stack Traces
anzuzeigen.

## Rack-Middleware

Sinatra baut auf [Rack](http://rack.github.io/), einem minimalistischen
Standard-Interface für Ruby-Webframeworks. Eines der interessantesten Features
für Entwickler ist der Support von Middlewares, die zwischen den Server und
die Anwendung geschaltet werden und so HTTP-Request und/oder Antwort
überwachen und/oder manipulieren können.

Sinatra macht das Erstellen von Middleware-Verkettungen mit der
Top-Level-Methode `use` zu einem Kinderspiel:

```ruby
require 'sinatra'
require 'meine_middleware'

use Rack::Lint
use MeineMiddleware

get '/hallo' do
  'Hallo Welt'
end
```

Die Semantik von `use` entspricht der gleichnamigen Methode der
[Rack::Builder](http://www.rubydoc.info/github/rack/rack/master/Rack/Builder)-DSL
(meist verwendet in Rackup-Dateien). Ein Beispiel dafür ist, dass die
`use`-Methode mehrere/verschiedene Argumente und auch Blöcke entgegennimmt:

```ruby
use Rack::Auth::Basic do |username, password|
  username == 'admin' && password == 'geheim'
end
```

Rack bietet eine Vielzahl von Standard-Middlewares für Logging, Debugging,
URL-Routing, Authentifizierung und Session-Verarbeitung. Sinatra verwendet
viele von diesen Komponenten automatisch, abhängig von der Konfiguration. So
muss `use` häufig nicht explizit verwendet werden.

Hilfreiche Middleware gibt es z.B. hier:
[rack](https://github.com/rack/rack/tree/master/lib/rack),
[rack-contrib](https://github.com/rack/rack-contrib#readme),
oder im [Rack wiki](https://github.com/rack/rack/wiki/List-of-Middleware).

## Testen

Sinatra-Tests können mit jedem auf Rack aufbauendem Test-Framework geschrieben
werden. [Rack::Test](http://www.rubydoc.info/github/brynary/rack-test/master/frames)
wird empfohlen:

```ruby
require 'my_sinatra_app'
require 'minitest/autorun'
require 'rack/test'

class MyAppTest < Minitest::Test
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def test_my_default
    get '/'
    assert_equal 'Hallo Welt!', last_response.body
  end

  def test_with_params
    get '/meet', :name => 'Frank'
    assert_equal 'Hallo Frank!', last_response.body
  end

  def test_with_rack_env
    get '/', {}, 'HTTP_USER_AGENT' => 'Songbird'
    assert_equal "Du verwendest Songbird!", last_response.body
  end
end
```

Hinweis: Wird Sinatra modular verwendet, muss <tt>Sinatra::Application</tt> mit
dem Namen der Applikations-Klasse ersetzt werden.

## Sinatra::Base - Middleware, Bibliotheken und modulare Anwendungen

Das Definieren einer Top-Level-Anwendung funktioniert gut für
Mikro-Anwendungen, hat aber Nachteile, wenn wiederverwendbare Komponenten wie
Middleware, Rails Metal, einfache Bibliotheken mit Server-Komponenten oder
auch Sinatra-Erweiterungen geschrieben werden sollen.

Das Top-Level geht von einer Konfiguration für eine Mikro-Anwendung aus (wie
sie z.B. bei einer einzelnen Anwendungsdatei, `./public` und `./views` Ordner,
Logging, Exception-Detail-Seite, usw.). Genau hier kommt `Sinatra::Base` ins
Spiel:

```ruby
require 'sinatra/base'

class MyApp < Sinatra::Base
  set :sessions, true
  set :foo, 'bar'

  get '/' do
    'Hallo Welt!'
  end
end
```

Die MyApp-Klasse ist eine unabhängige Rack-Komponente, die als Middleware,
Endpunkt oder via Rails Metal verwendet werden kann. Verwendet wird sie durch
`use` oder `run` von einer Rackup-`config.ru`-Datei oder als Server-Komponente
einer Bibliothek:

```ruby
MyApp.run! :host => 'localhost', :port => 9090
```

Die Methoden der `Sinatra::Base`-Subklasse sind genau dieselben wie die der
Top-Level-DSL. Die meisten Top-Level-Anwendungen können mit nur zwei
Veränderungen zu `Sinatra::Base` konvertiert werden:

*   Die Datei sollte `require 'sinatra/base'` anstelle von `require
    'sinatra/base'` aufrufen, ansonsten werden alle von Sinatras DSL-Methoden
    in den Top-Level-Namespace importiert.
*   Alle Routen, Error-Handler, Filter und Optionen der Applikation müssen in
    einer Subklasse von `Sinatra::Base` definiert werden.

`Sinatra::Base` ist ein unbeschriebenes Blatt. Die meisten Optionen sind per
Standard deaktiviert. Das betrifft auch den eingebauten Server. Siehe
[Optionen und Konfiguration](http://www.sinatrarb.com/configuration.html) für
Details über mögliche Optionen.

Damit eine App sich ähnlich wie eine klassische App verhält, kann man
auch eine Subclass von `Sinatra::Application` erstellen:

```ruby
require 'sinatra/base'

class MyApp < Sinatra::Application
  get '/' do
    'Hello world!'
  end
end
```

### Modularer vs. klassischer Stil

Entgegen häufiger Meinungen gibt es nichts gegen den klassischen Stil
einzuwenden. Solange es die Applikation nicht beeinträchtigt, besteht kein
Grund, eine modulare Applikation zu erstellen.

Der größte Nachteil der klassischen Sinatra Anwendung gegenüber einer
modularen ist die Einschränkung auf eine Sinatra Anwendung pro Ruby-Prozess.
Sollen mehrere zum Einsatz kommen, muss auf den modularen Stil umgestiegen
werden. Dabei ist es kein Problem klassische und modulare Anwendungen
miteinander zu vermischen.

Bei einem Umstieg, sollten einige Unterschiede in den Einstellungen beachtet
werden:

<table>
  <tr>
    <th>Szenario</th>
    <th>Classic</th>
    <th>Modular</th>
    <th>Modular</th>
  </tr>

  <tr>
    <td>app_file</td>
    <td>Sinatra ladende Datei</td>
    <td>Sinatra::Base subklassierende Datei</td>
    <td>Sinatra::Application subklassierende Datei</td>
  </tr>

  <tr>
    <td>run</td>
    <td>$0 == app_file</td>
    <td>false</td>
    <td>false</td>
  </tr>

  <tr>
    <td>logging</td>
    <td>true</td>
    <td>false</td>
    <td>true</td>
  </tr>

  <tr>
    <td>method_override</td>
    <td>true</td>
    <td>false</td>
    <td>true</td>
  </tr>

  <tr>
    <td>inline_templates</td>
    <td>true</td>
    <td>false</td>
    <td>true</td>
  </tr>

  <tr>
    <td>static</td>
    <td>true</td>
    <td>File.exist?(public_folder)</td>
    <td>true</td>
  </tr>
</table>

### Eine modulare Applikation bereitstellen

Es gibt zwei übliche Wege, eine modulare Anwendung zu starten. Zum einen über
`run!`:

```ruby
# mein_app.rb
require 'sinatra/base'

class MeinApp < Sinatra::Base
  # ... Anwendungscode hierhin ...

  # starte den Server, wenn die Ruby-Datei direkt ausgeführt wird
  run! if app_file == $0
end
```

Starte mit:

```shell
ruby mein_app.rb
```

Oder über eine `config.ru`-Datei, die es erlaubt, einen beliebigen
Rack-Handler zu verwenden:

```ruby
# config.ru (mit rackup starten)
require './mein_app'
run MeineApp
```

Starte:

```shell
rackup -p 4567
```

### Eine klassische Anwendung mit einer config.ru verwenden

Schreibe eine Anwendungsdatei:

```ruby
# app.rb
require 'sinatra'

get '/' do
  'Hallo Welt!'
end
```

sowie eine dazugehörige `config.ru`-Datei:

```ruby
require './app'
run Sinatra::Application
```

### Wann sollte eine config.ru-Datei verwendet werden?

Anzeichen dafür, dass eine `config.ru`-Datei gebraucht wird:

*   Es soll ein anderer Rack-Handler verwendet werden (Passenger, Unicorn,
    Heroku, ...).
*   Es gibt mehr als nur eine Subklasse von `Sinatra::Base`.
*   Sinatra soll als Middleware verwendet werden, nicht als Endpunkt.


**Es gibt keinen Grund, eine `config.ru`-Datei zu verwenden, nur weil eine
Anwendung im modularen Stil betrieben werden soll. Ebenso wird keine Anwendung
mit modularem Stil benötigt, um eine `config.ru`-Datei zu verwenden.**

### Sinatra als Middleware nutzen

Es ist nicht nur möglich, andere Rack-Middleware mit Sinatra zu nutzen, es
kann außerdem jede Sinatra-Anwendung selbst als Middleware vor jeden
beliebigen Rack-Endpunkt gehangen werden. Bei diesem Endpunkt muss es sich
nicht um eine andere Sinatra-Anwendung handeln, es kann jede andere
Rack-Anwendung sein (Rails/Ramaze/Camping/...):

```ruby
require 'sinatra/base'

class LoginScreen < Sinatra::Base
  enable :sessions

  get('/login') { haml :login }

  post('/login') do
    if params['name'] == 'admin' && params['password'] == 'admin'
      session['user_name'] = params['name']
    else
      redirect '/login'
    end
  end
end

class MyApp < Sinatra::Base
  # Middleware wird vor Filtern ausgeführt
  use LoginScreen

  before do
    unless session['user_name']
      halt "Zugriff verweigert, bitte <a href='/login'>einloggen</a>."
    end
  end

  get('/') { "Hallo #{session['user_name']}." }
end
```

### Dynamische Applikationserstellung

Manche Situationen erfordern die Erstellung neuer Applikationen zur Laufzeit,
ohne dass sie einer Konstanten zugeordnet werden. Dies lässt sich mit
`Sinatra.new` erreichen:

```ruby
require 'sinatra/base'
my_app = Sinatra.new { get('/') { "hallo" } }
my_app.run!
```

Die Applikation kann mit Hilfe eines optionalen Parameters erstellt werden:

```ruby
# config.ru
require 'sinatra/base'

controller = Sinatra.new do
  enable :logging
  helpers MyHelpers
end

map('/a') do
  run Sinatra.new(controller) { get('/') { 'a' } }
end

map('/b') do
  run Sinatra.new(controller) { get('/') { 'b' } }
end
```

Das ist besonders dann interessant, wenn Sinatra-Erweiterungen getestet werden
oder Sinatra in einer Bibliothek Verwendung findet.

Ebenso lassen sich damit hervorragend Sinatra-Middlewares erstellen:

```ruby
require 'sinatra/base'

use Sinatra do
  get('/') { ... }
end

run RailsProject::Application
```

## Geltungsbereich und Bindung

Der Geltungsbereich (Scope) legt fest, welche Methoden und Variablen zur
Verfügung stehen.

### Anwendungs- oder Klassen-Scope

Jede Sinatra-Anwendung entspricht einer `Sinatra::Base`-Subklasse. Falls die
Top- Level-DSL verwendet wird (`require 'sinatra'`), handelt es sich um
`Sinatra::Application`, andernfalls ist es jene Subklasse, die explizit
angelegt wurde. Auf Klassenebene stehen Methoden wie `get` oder `before` zur
Verfügung, es gibt aber keinen Zugriff auf das `request`-Object oder die
`session`, da nur eine einzige Klasse für alle eingehenden Anfragen genutzt
wird.

Optionen, die via `set` gesetzt werden, sind Methoden auf Klassenebene:

```ruby
class MyApp < Sinatra::Base
  # Hey, ich bin im Anwendungsscope!
  set :foo, 42
  foo # => 42

  get '/foo' do
    # Hey, ich bin nicht mehr im Anwendungs-Scope!
  end
end
```

Im Anwendungs-Scope befindet man sich:

*   In der Anwendungs-Klasse.
*   In Methoden, die von Erweiterungen definiert werden.
*   Im Block, der an `helpers` übergeben wird.
*   In Procs und Blöcken, die an `set` übergeben werden.
*   Der an `Sinatra.new` übergebene Block


Auf das Scope-Objekt (die Klasse) kann wie folgt zugegriffen werden:

*   Über das Objekt, das an den `configure`-Block übergeben wird (`configure {
    |c| ... }`).
*   `settings` aus den anderen Scopes heraus.


### Anfrage- oder Instanz-Scope

Für jede eingehende Anfrage wird eine neue Instanz der Anwendungs-Klasse
erstellt und alle Handler in diesem Scope ausgeführt. Aus diesem Scope heraus
kann auf `request` oder `session` zugegriffen und Methoden wie `erb` oder
`haml` aufgerufen werden. Außerdem kann mit der `settings`-Method auf den
Anwendungs-Scope zugegriffen werden:

```ruby
class MyApp < Sinatra::Base
  # Hey, ich bin im Anwendungs-Scope!
  get '/neue_route/:name' do
    # Anfrage-Scope für '/neue_route/:name'
    @value = 42

    settings.get "/#{params['name']}" do
      # Anfrage-Scope für "/#{params['name']}"
      @value # => nil (nicht dieselbe Anfrage)
    end

    "Route definiert!"
  end
end
```

Im Anfrage-Scope befindet man sich:

*   In get, head, post, put, delete, options, patch, link und unlink Blöcken
*   In before und after Filtern
*   In Helfer-Methoden
*   In Templates


### Delegation-Scope

Vom Delegation-Scope aus werden Methoden einfach an den Klassen-Scope
weitergeleitet. Dieser verhält sich jedoch nicht 100%ig wie der Klassen-Scope,
da man nicht die Bindung der Klasse besitzt: Nur Methoden, die explizit als
delegierbar markiert wurden, stehen hier zur Verfügung und es kann nicht auf
die Variablen des Klassenscopes zugegriffen werden (mit anderen Worten: es
gibt ein anderes `self`). Weitere Delegationen können mit
`Sinatra::Delegator.delegate :methoden_name` hinzugefügt werden.

Im Delegation-Scop befindet man sich:

*   Im Top-Level, wenn `require 'sinatra'` aufgerufen wurde.
*   In einem Objekt, das mit dem `Sinatra::Delegator`-Mixin erweitert wurde.


Schau am besten im Code nach: Hier ist [Sinatra::Delegator
mixin](http://github.com/sinatra/sinatra/blob/master/lib/sinatra/base.rb#L1064
) definiert und wird in den [globalen Namespace
eingebunden](http://github.com/sinatra/sinatra/blob/master/lib/sinatra/main.rb

## Kommandozeile

Sinatra-Anwendungen können direkt von der Kommandozeile aus gestartet werden:

```shell
ruby myapp.rb [-h] [-x] [-e ENVIRONMENT] [-p PORT] [-h HOST] [-s HANDLER]
```

Die Optionen sind:

```
-h # Hilfe
-p # Port setzen (Standard ist 4567)
-h # Host setzen (Standard ist 0.0.0.0)
-e # Umgebung setzen (Standard ist development)
-s # Rack-Server/Handler setzen (Standard ist thin)
-x # Mutex-Lock einschalten (Standard ist off)
```

### Multi-threading

_Paraphrasiert von [dieser Antwort auf StackOverflow][so-answer] von Konstantin_

Sinatra erlegt kein Nebenläufigkeitsmodell auf, sondern überlässt dies dem
selbst gewählten Rack-Proxy (Server), so wie Thin, Puma oder WEBrick.
Sinatra selbst ist Thread-sicher, somit ist es kein Problem wenn der
Rack-Proxy ein anderes Threading-Modell für Nebenläufigkeit benutzt.
Das heißt, dass wenn der Server gestartet wird, dass man die korrekte
Aufrufsmethode benutzen sollte für den jeweiligen Rack-Proxy.
Das folgende Beispiel ist eine Veranschaulichung eines mehrprozessigen
Thin Servers:

``` ruby
# app.rb

require 'sinatra/base'

class App < Sinatra::Base
  get '/' do
    "Hello, World"
  end
end

App.run!

```

Um den Server zu starten, führt man das folgende Kommando aus:

``` shell
thin --threaded start
```

[so-answer]: http://stackoverflow.com/questions/6278817/is-sinatra-multi-threaded/6282999#6282999)

## Systemanforderungen

Die folgenden Versionen werden offiziell unterstützt:

<dl>
<dt>Ruby 1.8.7</dt>
<dd>1.8.7 wird vollständig unterstützt, ein Wechsel zu JRuby oder Rubinius wird
aber empfohlen. Ruby 1.8.7 wird noch bis Sinatra 2.0 unterstützt werden. Frühere
Versionen von Ruby sind nicht kompatibel mit Sinatra.</dd>

<dt>Ruby 1.9.2</dt>
<dd>1.9.2 wird mindestens bis Sinatra 1.5 voll unterstützt. Version 1.9.2p0
sollte nicht verwendet werden, da unter Sinatra immer wieder Segfaults
auftreten.</dd>

<dt>Ruby 1.9.3</dt>
<dd>1.9.3 wird vollständig unterstützt und empfohlen. Achtung, bei einem
Upgrade von einer früheren Version von Ruby zu Ruby 1.9.3 werden alle Sessions
ungültig. Ruby 1.9.3 wird bis Sinatra 2.0 unterstützt werden.</dd>

<dt>Ruby 2.x</dt>
<dd>2.x wird vollständig unterstützt.</dd>

<dt>Rubinius</dt>
<dd>Rubinius (Version >= 2.x) wird offiziell unterstützt. Es wird empfohlen, den
<a href="http://puma.io">Puma Server</a> zu installieren (<tt>gem install puma
</tt>)</dd>

<dt>JRuby</dt>
<dd>Aktuelle JRuby Versionen werden offiziell unterstützt. Es wird empfohlen,
keine C-Erweiterungen zu verwenden und als Server Trinidad zu verwenden
(<tt>gem install trinidad</tt>).</dd>
</dl>

Die nachfolgend aufgeführten Ruby-Implementierungen werden offiziell nicht von
Sinatra unterstützt, funktionieren aber normalerweise:

*   Ruby Enterprise Edition
*   Ältere Versionen von JRuby und Rubinius
*   MacRuby (<tt>gem install control_tower</tt> wird empfohlen), Maglev, IronRuby
*   Ruby 1.9.0 und 1.9.1

Nicht offiziell unterstützt bedeutet, dass wenn Sachen nicht funktionieren,
wir davon ausgehen, dass es nicht an Sinatra sondern an der jeweiligen
Implementierung liegt.

Im Rahmen unserer CI (Kontinuierlichen Integration) wird bereits ruby-head
(zukünftige Versionen von MRI) mit eingebunden. Es kann davon ausgegangen
werden, dass Sinatra MRI auch weiterhin vollständig unterstützen wird.

Sinatra sollte auf jedem Betriebssystem laufen, dass einen funktionierenden
Ruby-Interpreter aufweist.

Sinatra läuft aktuell nicht unter Cardinal, SmallRuby, BlueRuby oder Ruby <= 1.8.7.

## Der neuste Stand (The Bleeding Edge)

Um auf dem neusten Stand zu bleiben, kann der Master-Branch verwendet werden.
Er sollte recht stabil sein. Ebenso gibt es von Zeit zu Zeit prerelease Gems,
die so installiert werden:

```shell
gem install sinatra --pre
```

### Mit Bundler

Wenn die Applikation mit der neuesten Version von Sinatra und
[Bundler](http://bundler.io) genutzt werden soll, empfehlen wir den
nachfolgenden Weg.

Soweit Bundler noch nicht installiert ist:

```shell
gem install bundler
```

Anschließend wird eine `Gemfile`-Datei im Projektverzeichnis mit folgendem
Inhalt erstellt:

```ruby
source :rubygems
gem 'sinatra', :git => "git://github.com/sinatra/sinatra.git"

# evtl. andere Abhängigkeiten
gem 'haml'                    # z.B. wenn du Haml verwendest...
gem 'activerecord', '~> 3.0'  # ...oder ActiveRecord 3.x
```

Beachte: Hier sollten alle Abhängigkeiten eingetragen werden. Sinatras eigene,
direkte Abhängigkeiten (Tilt und Rack) werden von Bundler automatisch aus dem
Gemfile von Sinatra hinzugefügt.

Jetzt kannst du deine Applikation starten:

```shell
bundle exec ruby myapp.rb
```

### Eigenes Repository
Um auf dem neuesten Stand von Sinatras Code zu sein, kann eine lokale Kopie
angelegt werden. Gestartet wird in der Anwendung mit dem `sinatra/lib`-Ordner
im `LOAD_PATH`:

```shell
cd myapp
git clone git://github.com/sinatra/sinatra.git
ruby -Isinatra/lib myapp.rb
```

Alternativ kann der `sinatra/lib`-Ordner zum `LOAD_PATH` in der Anwendung
hinzugefügt werden:

```ruby
$LOAD_PATH.unshift File.dirname(__FILE__) + '/sinatra/lib'
require 'rubygems'
require 'sinatra'

get '/ueber' do
  "Ich laufe auf Version " + Sinatra::VERSION
end
```

Um Sinatra-Code von Zeit zu Zeit zu aktualisieren:

```shell
cd myproject/sinatra
git pull
```

### Gem erstellen

Aus der eigenen lokalen Kopie kann nun auch ein globales Gem gebaut werden:

```shell
git clone git://github.com/sinatra/sinatra.git
cd sinatra
rake sinatra.gemspec
rake install
```

Falls Gems als Root installiert werden sollen, sollte die letzte Zeile
folgendermaßen lauten:

```shell
sudo rake install
```

## Versions-Verfahren

Sinatra folgt dem sogenannten [Semantic Versioning](http://semver.org/), d.h.
SemVer und SemVerTag.

## Mehr

*   [Projekt-Website](http://www.sinatrarb.com/) - Ergänzende Dokumentation,
    News und Links zu anderen Ressourcen.
*   [Mitmachen](http://www.sinatrarb.com/contributing.html) - Einen Fehler
    gefunden? Brauchst du Hilfe? Hast du einen Patch?
*   [Issue-Tracker](https://github.com/sinatra/sinatra/issues)
*   [Twitter](https://twitter.com/sinatra)
*   [Mailing-Liste](http://groups.google.com/group/sinatrarb)
*   [#sinatra](irc://chat.freenode.net/#sinatra) auf http://freenode.net Es
    gibt dort auch immer wieder deutschsprachige Entwickler, die gerne weiterhelfen.
*   [Sinatra Book](https://github.com/sinatra/sinatra-book/) Kochbuch Tutorial
*   [Sinatra Recipes](http://recipes.sinatrarb.com/) Sinatra-Rezepte aus der
    Community
*   API Dokumentation für die [aktuelle
    Version](http://www.rubydoc.info//gems/sinatra) oder für
    [HEAD](http://www.rubydoc.info/github/sinatra/sinatra) auf http://rubydoc.info
*   [CI Server](https://travis-ci.org/sinatra/sinatra)
