# Sinatra
*Fontos megjegyzés: Ez a dokumentum csak egy fordítása az angol nyelvű
változatnak, és lehet, hogy nem naprakész.*

A Sinatra egy [DSL](https://en.wikipedia.org/wiki/Domain-specific_language)
webalkalmazások Ruby nyelven történő fejlesztéséhez, minimális
energiabefektetéssel:

```ruby
  # myapp.rb
  require 'sinatra'
  get '/' do
    'Helló Világ!'
  end
```

Telepítsd a gem-et és indítsd el az alkalmazást a következőképpen:

```ruby
  sudo gem install sinatra
  ruby myapp.rb
```

Az alkalmazás elérhető lesz itt: [http://localhost:4567](http://localhost:4567)

## Útvonalak (routes)

A Sinatrában az útvonalat egy HTTP metódus és egy URL-re illeszkedő minta
párosa alkotja. Minden egyes útvonalhoz tartozik egy blokk:

```ruby
  get '/' do
    .. megjelenítünk valamit ..
  end

  post '/' do
    .. létrehozunk valamit ..
  end

  put '/' do
    .. frissítünk valamit ..
  end

  delete '/' do
    .. törlünk valamit ..
  end
```

Az útvonalak illeszkedését a rendszer a definiálásuk sorrendjében
ellenőrzi. Sorrendben mindig az első illeszkedő útvonalhoz tartozó metódus kerül
meghívásra.

Az útvonalminták tartalmazhatnak paramétereket is, melyeket a `params`
hash-ből érhetünk el:

```ruby
  get '/hello/:name' do
    # illeszkedik a "GET /hello/foo" és a "GET /hello/bar" útvonalakra
    # ekkor params['name'] értéke 'foo' vagy 'bar' lesz
    "Helló #{params['name']}!"
  end
```

A kulcsszavas argumentumokat (named parameters) blokk paraméterek útján
is el tudod érni:

```ruby
  get '/hello/:name' do |n|
    "Helló #{n}!"
  end
```

Az útvonalmintákban szerepelhetnek joker paraméterek is, melyeket a
`params['splat']` tömbön keresztül tudunk elérni.

```ruby
  get '/say/*/to/*' do
    # illeszkedik a /say/hello/to/world mintára
    params['splat'] # => ["hello", "world"]
  end

  get '/download/*.*' do
    # illeszkedik a /download/path/to/file.xml mintára
    params['splat'] # => ["path/to/file", "xml"]
  end
```

Reguláris kifejezéseket is felvehetünk az útvonalba:

```ruby
  get /\A\/hello\/([\w]+)\z/ do
    "Helló, #{params['captures'].first}!"
  end
```

Vagy blokk paramétereket:

```ruby
  get %r{/hello/([\w]+)} do |c|
    "Helló, #{c}!"
  end
```

Az útvonalak azonban számos egyéb illeszkedési feltétel szerint is
tervezhetők, így például az user agent karakterláncot alapul véve:

```ruby
  get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
    "A Songbird #{params['agent'][0]} verzióját használod"
  end

  get '/foo' do
    # illeszkedik az egyéb user agentekre
  end
```

## Statikus állományok

A statikus fájlok kiszolgálása a `./public` könyvtárból
történik, de természetesen más könyvtárat is megadhatsz erre a célra,
mégpedig a :public_folder kapcsoló beállításával:

  set :public_folder, File.dirname(__FILE__) + '/static'

Fontos megjegyezni, hogy a nyilvános könyvtár neve nem szerepel az URL-ben.
A ./public/css/style.css fájl az
`http://example.com/css/style.css` URL-en lesz elérhető.

## Nézetek és Sablonok

A sablonfájlokat rendszerint a  `./views` könyvtárba helyezzük, de
itt is lehetőség nyílik egyéb könyvtár használatára:

  set :views, File.dirname(__FILE__) + '/templates'

Nagyon fontos észben tartani, hogy a sablononkra mindig szimbólumokkal
hivatkozunk, még akkor is, ha egyéb (ebben az esetben a
:'subdir/template') könyvtárban tároljuk őket. A renderelő
metódusok minden, nekik közvetlenül átadott karakterláncot megjelenítenek.

### Haml sablonok

HAML sablonok rendereléséhez szükségünk lesz a haml gem-re vagy könyvtárra:

```ruby
  # Importáljuk be a haml-t az alkalmazásba
  require 'haml'

  get '/' do
    haml :index
  end
```

Ez szépen lerendereli a `./views/index.haml` sablont.

A [Haml kapcsolói](http://haml.hamptoncatlin.com/docs/rdoc/classes/Haml.html)
globálisan is beállíthatók a Sinatra konfigurációi között, lásd az
[Options and Configurations](http://www.sinatrarb.com/configuration.html) lapot.
A globális beállításokat lehetőségünk van felülírni metódus szinten is.

```ruby
  set :haml, {:format => :html5 } # az alapértelmezett Haml formátum az :xhtml

  get '/' do
    haml :index, :haml_options => {:format => :html4 } # immár felülírva
  end
```

### Erb sablonok

  # Importáljuk be az erb-t az alkalmazásba

```ruby
  require 'erb'

  get '/' do
    erb :index
  end
```

Ez a `./views/index.erb` sablont fogja lerenderelni.

### Builder sablonok

Szükségünk lesz a builder gem-re vagy könyvtárra a builder sablonok
rendereléséhez:

  # Importáljuk be a builder-t az alkalmazásba

```ruby
  require 'builder'

  get '/' do
    builder :index
  end
```

Ez pedig a `./views/index.builder` állományt fogja renderelni.

### Sass sablonok

Sass sablonok használatához szükség lesz a haml gem-re vagy könyvtárra:

  # Be kell importálni a haml, vagy a sass könyvtárat

```ruby
  require 'sass'

  get '/stylesheet.css' do
    sass :stylesheet
  end
```

Így a `./views/stylesheet.sass` fájl máris renderelhető.

A [Sass kapcsolói](http://haml.hamptoncatlin.com/docs/rdoc/classes/Sass.html)
globálisan is beállíthatók a Sinatra konfigurációi között, lásd az
[Options and Configurations](http://www.sinatrarb.com/configuration.html) lapot.
A globális beállításokat lehetőségünk van felülírni metódus szinten is.

```ruby
  set :sass, {:style => :compact } # az alapértelmezett Sass stílus a :nested

  get '/stylesheet.css' do
    sass :stylesheet, :sass_options => {:style => :expanded } # felülírva
  end
```

### Beágyazott sablonok

```ruby
  get '/' do
    haml '%div.title Helló Világ'
  end
```

Lerendereli a beágyazott sablon karakerláncát.

### Változók elérése a sablonokban

A sablonok ugyanabban a kontextusban kerülnek kiértékelésre, mint az
útvonal metódusok (route handlers). Az útvonal metódusokban megadott
változók közvetlenül elérhetőek lesznek a sablonokban:

```ruby
  get '/:id' do
    @foo = Foo.find(params['id'])
    haml '%h1= @foo.name'
  end
```

De megadhatod egy lokális változókat tartalmazó explicit hash-ben is:

```ruby
  get '/:id' do
    foo = Foo.find(params['id'])
    haml '%h1= foo.name', :locals => { :foo => foo }
  end
```

Ezt leginkább akkor érdemes megtenni, ha partial-eket akarunk renderelni
valamely más sablonból.

### Fájlon belüli sablonok

Sablonokat úgy is megadhatunk, hogy egyszerűen az alkalmazás fájl
végére begépeljük őket:

```ruby
  require 'rubygems'
  require 'sinatra'

  get '/' do
    haml :index
  end

  __END__

  @@ layout
  %html
    = yield

  @@ index
  %div.title Helló Világ!!!!!
```

Megjegyzés: azok a fájlon belüli sablonok, amelyek az alkalmazás fájl végére
kerülnek és függnek a sinatra könyvtártól, automatikusan betöltődnek.
Ha ugyanezt más alkalmazásfájlban is szeretnéd megtenni, hívd meg
a <tt>use_in_file_templates!</tt> metódust az adott fájlban.

### Kulcsszavas sablonok

Sablonokat végül a felsőszintű <tt>template</tt> metódussal is
definiálhatunk:

```ruby
  template :layout do
    "%html\n  =yield\n"
  end

  template :index do
    '%div.title Helló Világ!'
  end

  get '/' do
    haml :index
  end
```

Ha létezik "layout" nevű sablon, akkor az minden esetben meghívódik, amikor
csak egy sablon renderelésre kerül. A layoutokat ki lehet kapcsolni a
`:layout => false` meghívásával.

```ruby
  get '/' do
    haml :index, :layout => !request.xhr?
  end
```

## Helperek

Használd a felső szintű <tt>helpers</tt> metódust azokhoz a helper
függvényekhez, amiket az útvonal metódusokban és a sablonokban akarsz
használni:

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

## Szűrők (filters)

Az előszűrők (before filter) az adott hívás kontextusában minden egyes
kérés alkalmával kiértékelődnek, így módosíthatják a kérést és a
választ egyaránt. A szűrőkbe felvett példányváltozók elérhetőek lesznek
az útvonalakban és a sablonokban is:

```ruby
  before do
    @note = 'Csá!'
    request.path_info = '/foo/bar/baz'
  end

  get '/foo/*' do
    @note #=> 'Szeva!'
    params['splat'] #=> 'bar/baz'
  end
```

Az utószűrők az egyes kérések után, az adott kérés kontextusában kerülnek
kiértékelésre, így ezek is képesek módosítani a kérést és a választ egyaránt.
Az előszűrőkben és úvonalakban létrehozott példányváltozók elérhetőek lesznek
az utószűrők számára:

```ruby
  after do
    puts response.status
  end
```

## Megállítás

Egy kérés szűrőben vagy útvonalban történő azonnal blokkolásához
használd a következő parancsot:

  halt

A megállításkor egy blokktörzset is megadhatsz ...

  halt 'ez fog megjelenni a törzsben'

Vagy állítsd be a HTTP státuszt és a törzset is egyszerre ...

  halt 401, 'menj innen!'

## Passzolás

Az útvonalak továbbadhatják a végrehajtást egy másik útvonalnak
a `pass` függvényhívással:

```ruby
  get '/guess/:who' do
    pass unless params['who'] == 'Frici'
    "Elkaptál!"
  end

  get '/guess/*' do
    "Elhibáztál!"
  end
```

Az útvonal blokkja azonnal kilép és átadja a vezérlést a következő
illeszkedő útvonalnak. Ha nem talál megfelelő útvonalat, a Sinatra
egy 404-es hibával tér vissza.

## Beállítások

Csak indításkor, de minden környezetre érvényesen fusson le:

```ruby
  configure do
    ...
  end
```

Csak akkor fusson le, ha a környezet (a RACK_ENV környezeti változóban)
`:production`-ra van állítva:

```ruby
  configure :production do
    ...
  end
```

Csak akkor fusson le, ha a környezet <tt>:production</tt> vagy <tt>:test</tt>:

```ruby
  configure :production, :test do
    ...
  end
```

## Hibakezelés

A hibakezelők ugyanabban a kontextusban futnak le, mint az útvonalak és
előszűrők, ezért számukra is elérhetőek mindazok a könyvtárak, amelyek
az utóbbiak rendelkezésére is állnak; így például a `haml`,
az `erb`, a `halt` stb.

### Nem található

Amikor a `Sinatra::NotFound` kivétel fellép, vagy a válasz HTTP
státuszkódja 404-es, mindig a `not_found` metódus hívódik meg.

```ruby
  not_found do
    'Sehol sem találom, amit keresel'
  end
```

### Hiba

Az `error` metódus hívódik meg olyankor, amikor egy útvonal, blokk vagy
előszűrő kivételt vált ki. A kivétel objektum lehívható a
`sinatra.error` Rack változótól:

```ruby
  error do
    'Elnézést, de valami szörnyű hiba lépett fel - ' + env['sinatra.error'].message
  end
```

Egyéni hibakezelés:

```ruby
  error MyCustomError do
    'Szóval az van, hogy...' + env['sinatra.error'].message
  end
```

És amikor fellép:

```ruby
  get '/' do
    raise MyCustomError, 'valami nem stimmel!'
  end
```

Ez fog megjelenni:

  Szóval az van, hogy... valami nem stimmel!

A Sinatra speciális `not_found` és `error` hibakezelőket
használ, amikor a futtatási környezet fejlesztői módba van kapcsolva.

## Mime típusok

A `send_file` metódus használatakor, vagy statikus fájlok
kiszolgálásakor előfordulhat, hogy a Sinatra nem ismeri fel a fájlok
mime típusát. Ilyenkor használd a +mime_type+ kapcsolót a fájlkiterjesztés
bevezetéséhez:

```ruby
  mime_type :foo, 'text/foo'
```

## Rack Middleware

A Sinatra egy Ruby keretrendszerek számára kifejlesztett egyszerű és szabványos
interfészre, a [Rack](http://rack.github.io/) -re épül. A Rack fejlesztői
szempontból egyik legérdekesebb jellemzője, hogy támogatja az úgynevezett
"middleware" elnevezésű komponenseket, amelyek beékelődnek a szerver és az
alkalmazás közé, így képesek megfigyelni és/vagy módosítani a HTTP
kéréseket és válaszokat. Segítségükkel különféle, egységesen működő
funkciókat építhetünk be rendszerünkbe.

A Sinatra keretrendszerben gyerekjáték a Rack middleware-ek behúzása a
`use` metódus segítségével:

```ruby
  require 'sinatra'
  require 'my_custom_middleware'

  use Rack::Lint
  use MyCustomMiddleware

  get '/hello' do
    'Helló Világ'
  end
```

A `use` metódus szemantikája megegyezik a
[Rack::Builder](http://www.rubydoc.info/github/rack/rack/master/Rack/Builder) DSL-ben
használt +use+ metóduséval (az említett DSL-t leginkább rackup állományokban
használják). Hogy egy példát említsünk, a `use` metódus elfogad
változókat és blokkokat egyaránt, akár kombinálva is ezeket:

```ruby
  use Rack::Auth::Basic do |username, password|
    username == 'admin' && password == 'titkos'
  end
```

A Rack terjesztéssel egy csomó alap middleware komponens is érkezik,
amelyekkel a naplózás, URL útvonalak megadása, autentikáció és
munkamenet-kezelés könnyen megvalósítható. A Sinatra ezek közül elég
sokat automatikusan felhasznál a beállításoktól függően, így ezek
explicit betöltésével (+use+) nem kell bajlódnod.

## Tesztelés

Sinatra teszteket bármely Rack alapú tesztelő könyvtárral vagy
keretrendszerrel készíthetsz. Mi a [Rack::Test](http://gitrdoc.com/brynary/rack-test)
könyvtárat ajánljuk:

```ruby
  require 'my_sinatra_app'
  require 'rack/test'

  class MyAppTest < Minitest::Test
    include Rack::Test::Methods

    def app
      Sinatra::Application
    end

    def test_my_default
      get '/'
      assert_equal 'Helló Világ!', last_response.body
    end

    def test_with_params
      get '/meet', :name => 'Frici'
      assert_equal 'Helló Frici!', last_response.body
    end

    def test_with_rack_env
      get '/', {}, 'HTTP_USER_AGENT' => 'Songbird'
      assert_equal "Songbird-öt használsz!", last_response.body
    end
  end
```

Megjegyzés: A beépített Sinatra::Test és Sinatra::TestHarness osztályok
a 0.9.2-es kiadástól kezdve elavultnak számítanak.

## Sinatra::Base - Middleware-ek, könyvtárak és moduláris alkalmazások

Az alkalmazást felső szinten építeni megfelelhet mondjuk egy kisebb
app esetén, ám kifejezetten károsnak bizonyulhat olyan komolyabb,
újra felhasználható komponensek készítésekor, mint például egy Rack
middleware, Rails metal, egyszerűbb kiszolgáló komponenssel bíró
könyvtárak vagy éppen Sinatra kiterjesztések. A felső szintű DSL
bepiszkítja az Objektum névteret, ráadásul kisalkalmazásokra szabott
beállításokat feltételez (így például egyetlen alkalmazásfájl,
`./public`
és `./views` könyvtár meglétét, naplózást, kivételkezelő oldalt stb.).
Itt jön a képbe a Sinatra::Base osztály:

```ruby
  require 'sinatra/base'

  class MyApp < Sinatra::Base
    set :sessions, true
    set :foo, 'bar'

    get '/' do
      'Helló Világ!'
    end
  end
```

A MyApp osztály immár önálló Rack komponensként, mondjuk Rack middleware-ként
vagy alkalmazásként, esetleg Rails metal-ként is tud működni. Közvetlenül
használhatod (`use`) vagy futtathatod (`run`) az osztályodat egy rackup
konfigurációs állományban (`config.ru`), vagy egy szerverkomponenst
tartalmazó könyvtár vezérlésekor:

```ruby
   MyApp.run! :host => 'localhost', :port => 9090
```

A Sinatra::Base gyermekosztályaiban elérhető metódusok egyúttal a felső
szintű DSL-en keresztül is hozzáférhetők. A legtöbb felső szintű
alkalmazás átalakítható Sinatra::Base alapú komponensekké két lépésben:

* A fájlban nem a `sinatra`, hanem a `sinatra/base` osztályt kell
  beimportálni, mert egyébként az összes Sinatra DSL metódus a fő
  névtérbe kerül.
* Az alkalmazás útvonalait, hibakezelőit, szűrőit és beállításait
  a Sinatra::Base osztály gyermekosztályaiban kell megadni.

A `Sinatra::Base` osztály igazából egy üres lap: a legtöbb funkció
alapból ki van kapcsolva, beleértve a beépített szervert is. A
beállításokkal és az egyes kapcsolók hatásával az
[Options and Configuration](http://www.sinatrarb.com/configuration.html) lap
foglalkozik.

Széljegyzet: A Sinatra felső szintű DSL-je egy egyszerű delegációs
rendszerre épül. A Sinatra::Application osztály - a Sinatra::Base egy
speciális osztályaként - fogadja az összes :get, :put, :post,
:delete, :before, :error, :not_found, :configure és :set üzenetet,
ami csak a felső szintre beérkezik. Érdemes utánanézned a kódban,
miképp [kerül be](http://github.com/sinatra/sinatra/blob/master/lib/sinatra/main.rb#L25)
a [Sinatra::Delegator mixin](http://github.com/sinatra/sinatra/blob/master/lib/sinatra/base.rb#L1064)
a fő névtérbe.

## Parancssori lehetőségek

Sinatra alkalmazásokat közvetlenül futtathatunk:

```
  ruby myapp.rb [-h] [-x] [-e ENVIRONMENT] [-p PORT] [-s HANDLER]
```

Az alábbi kapcsolókat ismeri fel a rendszer:

  -h # segítség
  -p # a port beállítása (alapértelmezés szerint ez a 4567-es)
  -e # a környezet beállítása (alapértelmezés szerint ez a development)
  -s # a rack szerver/handler beállítása (alapértelmezetten ez a thin)
  -x # a mutex lock bekapcsolása (alapértelmezetten ki van kapcsolva)

## Fejlesztői változat

Ha a Sinatra legfrissebb, fejlesztői változatát szeretnéd használni,
készíts egy helyi másolatot és indítsd az alkalmazásodat úgy,
hogy a `sinatra/lib` könyvtár elérhető legyen a
`LOAD_PATH`-on:

```
  cd myapp
  git clone git://github.com/sinatra/sinatra.git
  ruby -Isinatra/lib myapp.rb
```

De hozzá is adhatod a <tt>sinatra/lib</tt> könyvtárat a <tt>LOAD_PATH</tt>-hoz
az alkalmazásodban:

```ruby
  $LOAD_PATH.unshift File.dirname(__FILE__) + '/sinatra/lib'
  require 'rubygems'
  require 'sinatra'

  get '/about' do
    "A következő változatot futtatom " + Sinatra::VERSION
  end
```

A Sinatra frissítését később így végezheted el:

```
  cd myproject/sinatra
  git pull
```

## További információk

* [A projekt weboldala](http://www.sinatrarb.com/) - Kiegészítő dokumentáció,
  hírek, hasznos linkek
* [Közreműködés](http://www.sinatrarb.com/contributing.html) - Hibát találtál?
  Segítségre van szükséged? Foltot küldenél be?
* [Lighthouse](http://sinatra.lighthouseapp.com) - Hibakövetés és kiadások
* [Twitter](https://twitter.com/sinatra)
* [Levelezőlista](http://groups.google.com/group/sinatrarb)
* [IRC: #sinatra](irc://chat.freenode.net/#sinatra) a http://freenode.net címen
