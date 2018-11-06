# Sinatra

*Atención: Este documento es una traducción de la versión en inglés y puede estar desactualizado.*

Sinatra es un
[DSL](https://es.wikipedia.org/wiki/Lenguaje_específico_del_dominio) para
crear aplicaciones web rápidamente en Ruby con un mínimo esfuerzo:

```ruby
# miapp.rb
require 'sinatra'

get '/' do
  'Hola mundo!'
end
```

Instalar la gema y correr la aplicación con:

```shell
gem install sinatra
ruby miapp.rb
```

Ver en [http://localhost:4567](http://localhost:4567).

Se recomienda ejecutar `gem install thin`, porque Sinatra lo utilizará si está disponible.

## Rutas

En Sinatra, una ruta es un método HTTP junto a un patrón de un URL.
Cada ruta está asociada a un bloque:

```ruby
get '/' do
  .. mostrar algo ..
end

post '/' do
  .. crear algo ..
end

put '/' do
  .. reemplazar algo ..
end

patch '/' do
  .. modificar algo ..
end

delete '/' do
  .. aniquilar algo ..
end

options '/' do
  .. informar algo ..
end

link '/' do
  .. afiliar a algo ..
end

unlink '/' do
  .. separar algo ..
end

```

Las rutas son comparadas en el orden en el que son definidas. La primera ruta
que coincide con la petición es escogida.

Los patrones de las rutas pueden incluir parámetros nombrados, accesibles a
través del hash `params`:

```ruby
get '/hola/:nombre' do
  # coincide con "GET /hola/foo" y "GET /hola/bar"
  # params['nombre'] es 'foo' o 'bar'
  "Hola #{params['nombre']}!"
end
```

También puede acceder a los parámetros nombrados usando parámetros de bloque:

```ruby
get '/hola/:nombre' do |n|
  # coincide con "GET /hola/foo" y "GET /hola/bar"
  # params['nombre'] es 'foo' o 'bar'
  # n almacena params['nombre']
  "Hola #{n}!"
end
```

Los patrones de ruta también pueden incluir parámetros splat (o wildcard),
accesibles a través del arreglo `params['splat']`:

```ruby
get '/decir/*/al/*' do
  # coincide con /decir/hola/al/mundo
  params['splat'] # => ["hola", "mundo"]
end

get '/descargar/*.*' do
  # coincide con /descargar/path/al/archivo.xml
  params['splat'] # => ["path/al/archivo", "xml"]
end
```

O, con parámetros de bloque:

```ruby
get '/descargar/*.*' do |path, ext|
  [path, ext] # => ["path/al/archivo", "xml"]
end
```

Rutas con Expresiones Regulares:

```ruby
get /\A\/hola\/([\w]+)\z/ do
  "Hola, #{params['captures'].first}!"
end
```

O con un parámetro de bloque:

```ruby
get %r{/hola/([\w]+)} do |c|
  "Hola, #{c}!"
end
```

Los patrones de ruta pueden contener parámetros opcionales:

```ruby
get '/posts/:formato?' do
  # coincide con "GET /posts/" y además admite cualquier extensión, por
  # ejemplo, "GET /posts/json", "GET /posts/xml", etc.
end
```

A propósito, a menos que desactives la protección para el ataque *path
traversal* (ver más abajo), el path de la petición puede ser modificado
antes de que se compare con los de tus rutas.

## Condiciones

Las rutas pueden incluir una variedad de condiciones de selección, como por
ejemplo el user agent:

```ruby
get '/foo', :agent => /Songbird (\d\.\d)[\d\/]*?/ do
  "Estás usando la versión de Songbird #{params['agent'][0]}"
end

get '/foo' do
  # Coincide con navegadores que no sean songbird
end
```

Otras condiciones disponibles son `host_name` y `provides`:

```ruby
get '/', :host_name => /^admin\./ do
  "Área de Administración, Acceso denegado!"
end

get '/', :provides => 'html' do
  haml :index
end

get '/', :provides => ['rss', 'atom', 'xml'] do
  builder :feed
end
```

Puede definir sus propias condiciones fácilmente:

```ruby
set(:probabilidad) { |valor| condition { rand <= valor } }

get '/gana_un_auto', :probabilidad => 0.1 do
  "Ganaste!"
end

get '/gana_un_auto' do
  "Lo siento, perdiste."
end
```

Si su condición acepta más de un argumento, puede pasarle un arreglo. Al
definir la condición, se puede utilizar el operador splat en
la lista de parámetros:

```ruby
set(:autorizar) do |*roles|   # <- mirá el splat
  condition do
    unless sesion_iniciada? && roles.any? {|rol| usuario_actual.tiene_rol? rol }
      redirect "/iniciar_sesion/", 303
    end
  end
end

get "/mi/cuenta/", :autorizar => [:usuario, :administrador] do
  "Detalles de mi cuenta"
end

get "/solo/administradores/", :autorizar => :administrador do
  "Únicamente para administradores!"
end
```

### Valores de Retorno

El valor de retorno de un bloque de ruta que determina al menos el cuerpo de la
respuesta que se le pasa al cliente HTTP o al siguiente middleware en la pila
de Rack. Lo más común es que sea un string, como en los ejemplos anteriores.
Sin embargo, otros valores también son aceptados.

Puede devolver cualquier objeto que sea una respuesta Rack válida, un objeto
que represente el cuerpo de una respuesta Rack o un código de estado HTTP:

* Un arreglo con tres elementos: `[estado (Fixnum), cabeceras (Hash), cuerpo de
  la respuesta (responde a #each)]`
* Un arreglo con dos elementos: `[estado (Fixnum), cuerpo de la respuesta
  (responde a #each)]`
* Un objeto que responde a `#each` y que le pasa únicamente strings al bloque
  dado
* Un Fixnum representando el código de estado

De esa manera, podemos fácilmente implementar un ejemplo de streaming:

```ruby
class Stream
  def each
    100.times { |i| yield "#{i}\n" }
  end
end

get('/') { Stream.new }
```

### Comparadores de Rutas Personalizados

Como se mostró anteriormente, Sinatra permite utilizar strings y expresiones
regulares para definir las rutas. Sin embargo, la cosa no termina ahí. Podés
definir tus propios comparadores muy fácilmente:

```ruby
class PatronCualquieraMenos
  Match = Struct.new(:captures)

  def initialize(excepto)
    @excepto  = excepto
    @capturas = Match.new([])
  end

  def match(str)
    @capturas unless @excepto === str
  end
end

def cualquiera_menos(patron)
  PatronCualquieraMenos.new(patron)
end

get cualquiera_menos("/index") do
  # ...
end
```

Tenga en cuenta que el ejemplo anterior es un poco rebuscado. Un resultado
similar puede conseguirse más sencillamente:

```ruby
get // do
  pass if request.path_info == "/index"
  # ...
end
```

O, usando un lookahead negativo:

```ruby
get %r{^(?!/index$)} do
  # ...
end
```

### Archivos Estáticos

Los archivos estáticos son servidos desde el directorio público
`./public`. Puede especificar una ubicación diferente ajustando la
opción `:public_folder`:

```ruby
set :public_folder, File.dirname(__FILE__) + '/estaticos'
```

Note que el nombre del directorio público no está incluido en la URL. Por
ejemplo, el archivo `./public/css/style.css` se accede a través de
`http://ejemplo.com/css/style.css`.

Use la configuración `:static_cache_control` para agregar el encabezado
`Cache-Control` (ver la sección de configuración para más detalles).

### Vistas / Plantillas

Cada lenguaje de plantilla se expone a través de un método de renderizado que
lleva su nombre. Estos métodos simplemente devuelven un string:

```ruby
get '/' do
  erb :index
end
```

Renderiza `views/index.erb`.

En lugar del nombre de la plantilla podés proporcionar directamente el
contenido de la misma:

```ruby
get '/' do
  codigo = "<%= Time.now %>"
  erb codigo
end
```

Los métodos de renderizado, aceptan además un segundo argumento, el hash de
opciones:

```ruby
get '/' do
  erb :index, :layout => :post
end
```

Renderiza `views/index.erb` incrustado en `views/post.erb` (por
defecto, la plantilla `:index` es incrustada en `views/layout.erb` siempre y
cuando este último archivo exista).

Cualquier opción que Sinatra no entienda le será pasada al motor de renderizado
de la plantilla:

```ruby
get '/' do
  haml :index, :format => :html5
end
```

Además, puede definir las opciones para un lenguaje de plantillas de forma
general:

```ruby
set :haml, :format => :html5

get '/' do
  haml :index
end
```

Las opciones pasadas al método de renderizado tienen precedencia sobre las
definidas mediante `set`.

Opciones disponibles:

<dl>

  <dt>locals</dt>
  <dd>
    Lista de variables locales pasadas al documento. Resultan muy útiles cuando
    se combinan con parciales.
    Ejemplo: <tt>erb "<%= foo %>", :locals => {:foo => "bar"}</tt>
  </dd>

  <dt>default_encoding</dt>
  <dd>
    Encoding utilizado cuando el de un string es dudoso. Por defecto toma el
    valor de <tt>settings.default_encoding</tt>.
  </dd>

  <dt>views</dt>
  <dd>
    Directorio desde donde se cargan las vistas. Por defecto toma el valor de
    <tt>settings.views</tt>.
  </dd>

  <dt>layout</dt>
  <dd>
    Si es <tt>true</tt> o <tt>false</tt> indica que se debe usar, o no, un layout,
    respectivamente. También puede ser un símbolo que especifique qué plantilla
    usar. Ejemplo: <tt>erb :index, :layout => !request.xhr?</tt>
  </dd>

  <dt>content_type</dt>
  <dd>
    Content-Type que produce la plantilla. El valor por defecto depende de cada
    lenguaje de plantillas.
  </dd>

  <dt>scope</dt>
  <dd>
    Ámbito en el que se renderiza la plantilla. Por defecto utiliza la instancia
    de la aplicación. Tené en cuenta que si cambiás esta opción las variables de
    instancia y los helpers van a dejar de estar disponibles.
  </dd>

  <dt>layout_engine</dt>
  <dd>
    Motor de renderizado de plantillas que usa para el layout. Resulta
    conveniente para lenguajes que no soportan layouts. Por defecto toma el valor
    del motor usado para renderizar la plantilla.
    Ejemplo: <tt>set :rdoc, :layout_engine => :erb</tt>
  </dd>

  <dd>
    Se asume que las plantillas están ubicadas directamente bajo el directorio
    <tt>./views</tt>. Para usar un directorio de vistas diferente:
    <tt>set :views, settings.root + '/plantillas'</tt>
  </dd>

  <dd>
    Es importante acordarse que siempre tenés que referenciar a las plantillas con
    símbolos, incluso cuando se encuentran en un subdirectorio (en este caso
    tenés que usar: `:'subdir/plantilla'` o `'subdir/plantilla'.to_sym`). Tenés que
    usar un símbolo porque los métodos de renderización van a renderizar
    directamente cualquier string que se les pase como argumento.
  </dd>
</dl>

### Lenguajes de Plantillas Disponibles

Algunos lenguajes tienen varias implementaciones. Para especificar que
implementación usar (y para ser thread-safe), deberías requerirla antes de
usarla:

```ruby
require 'rdiscount' # o require 'bluecloth'
get('/') { markdown :index }
```

### Plantillas Haml

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://haml.info/" title="haml">haml</a></td>
  </tr>
  <tr>
    <td>Expresiones de Archivo</td>
    <td><tt>.haml</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>haml :index, :format => :html5</tt></td>
  </tr>
</table>

### Plantillas Erb

<table>
  <tr>
    <td>Dependencias</td>
    <td>
      <a href="http://www.kuwata-lab.com/erubis/" title="erubis">erubis</a>
      o erb (incluida en Ruby)
    </td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.erb</tt>, <tt>.rhtml</tt> o <tt>.erubis</tt> (solamente con Erubis)</td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>erb :index</tt></td>
  </tr>
</table>

### Plantillas Builder

<table>
  <tr>
    <td>Dependencias</td>
    <td>
      <a href="https://github.com/jimweirich/builder" title="builder">builder</a>
    </td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.builder</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>builder { |xml| xml.em "hola" }</tt></td>
  </tr>
</table>

Además, acepta un bloque con la definición de la plantilla (ver ejemplo).

### Plantillas Nokogiri

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://www.nokogiri.org/" title="nokogiri">nokogiri</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.nokogiri</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>nokogiri { |xml| xml.em "hola" }</tt></td>
  </tr>
</table>

Además, acepta un bloque con la definición de la plantilla (ver ejemplo).

### Plantillas Sass

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.sass</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>sass :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

### Plantillas SCSS

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://sass-lang.com/" title="sass">sass</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.scss</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>scss :stylesheet, :style => :expanded</tt></td>
  </tr>
</table>

### Plantillas Less

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://lesscss.org/" title="less">less</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.less</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>less :stylesheet</tt></td>
  </tr>
</table>

### Plantillas Liquid

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://liquidmarkup.org/" title="liquid">liquid</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.liquid</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>liquid :index, :locals => { :clave => 'valor' }</tt></td>
  </tr>
</table>

Como no va a poder llamar a métodos de Ruby (excepto por `yield`) desde una
plantilla Liquid, casi siempre va a querer pasarle locales.

### Plantillas Markdown

<table>
  <tr>
    <td>Dependencias</td>
    <td>
      <a href="https://github.com/davidfstr/rdiscount" title="RDiscount">RDiscount</a>,
      <a href="https://github.com/vmg/redcarpet" title="RedCarpet">RedCarpet</a>,
      <a href="http://deveiate.org/projects/BlueCloth" title="BlueCloth">BlueCloth</a>,
      <a href="http://kramdown.gettalong.org/" title="kramdown">kramdown</a> o
      <a href="https://github.com/bhollis/maruku" title="maruku">maruku</a>
    </td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.markdown</tt>, <tt>.mkd</tt> y <tt>.md</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>markdown :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

No es posible llamar métodos desde markdown, ni pasarle locales. Por lo tanto,
generalmente va a usarlo en combinación con otro motor de renderizado:

```ruby
erb :resumen, :locals => { :texto => markdown(:introduccion) }
```

Tenga en cuenta que también podés llamar al método `markdown` desde otras
plantillas:

```ruby
%h1 Hola Desde Haml!
%p= markdown(:saludos)
```

Como no puede utilizar Ruby desde Markdown, no puede usar layouts escritos en
Markdown. De todos modos, es posible usar un motor de renderizado para el
layout distinto al de la plantilla pasando la opción `:layout_engine`.

### Plantillas Textile

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://redcloth.org/" title="RedCloth">RedCloth</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.textile</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>textile :index, :layout_engine => :erb</tt></td>
  </tr>
</table>

No es posible llamar métodos desde textile, ni pasarle locales. Por lo tanto,
generalmente vas a usarlo en combinación con otro motor de renderizado:

```ruby
erb :resumen, :locals => { :texto => textile(:introduccion) }
```

Tené en cuenta que también podés llamar al método `textile` desde otras
plantillas:

```ruby
%h1 Hola Desde Haml!
%p= textile(:saludos)
```

Como no podés utilizar Ruby desde Textile, no podés usar layouts escritos en
Textile. De todos modos, es posible usar un motor de renderizado para el
layout distinto al de la plantilla pasando la opción `:layout_engine`.

### Plantillas RDoc

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://rdoc.sourceforge.net/" title="RDoc">RDoc</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.rdoc</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>rdoc :README, :layout_engine => :erb</tt></td>
  </tr>
</table>

No es posible llamar métodos desde rdoc, ni pasarle locales. Por lo tanto,
generalmente vas a usarlo en combinación con otro motor de renderizado:

```ruby
erb :resumen, :locals => { :texto => rdoc(:introduccion) }
```

Tené en cuenta que también podés llamar al método `rdoc` desde otras
plantillas:

```ruby
%h1 Hola Desde Haml!
%p= rdoc(:saludos)
```

Como no podés utilizar Ruby desde RDoc, no podés usar layouts escritos en RDoc.
De todos modos, es posible usar un motor de renderizado para el layout distinto
al de la plantilla pasando la opción `:layout_engine`.

### Plantillas Radius

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="https://github.com/jlong/radius" title="Radius">Radius</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.radius</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>radius :index, :locals => { :clave => 'valor' }</tt></td>
  </tr>
</table>

Desde que no se puede utilizar métodos de Ruby (excepto por `yield`) de una
plantilla Radius, casi siempre se necesita pasar locales.

### Plantillas Markaby

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://markaby.github.io/" title="Markaby">Markaby</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.mab</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>markaby { h1 "Bienvenido!" }</tt></td>
  </tr>
</table>

Además, acepta un bloque con la definición de la plantilla (ver ejemplo).

### Plantillas RABL

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="https://github.com/nesquena/rabl" title="Rabl">Rabl</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.rabl</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>rabl :index</tt></td>
  </tr>
</table>

### Plantillas Slim

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="http://slim-lang.com/" title="Slim Lang">Slim Lang</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.slim</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>slim :index</tt></td>
  </tr>
</table>

### Plantillas Creole

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="https://github.com/minad/creole" title="Creole">Creole</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.creole</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>creole :wiki, :layout_engine => :erb</tt></td>
  </tr>
</table>

No es posible llamar métodos desde creole, ni pasarle locales. Por lo tanto,
generalmente va a usarlo en combinación con otro motor de renderizado:

```ruby
erb :resumen, :locals => { :texto => cerole(:introduccion) }
```

Debe tomar en cuenta que también puede llamar al método `creole` desde otras
plantillas:

```ruby
%h1 Hola Desde Haml!
%p= creole(:saludos)
```

Como no podés utilizar Ruby desde Creole, no podés usar layouts escritos en
Creole. De todos modos, es posible usar un motor de renderizado para el layout
distinto al de la plantilla pasando la opción `:layout_engine`.

### Plantillas CoffeeScript

<table>
  <tr>
    <td>Dependencias</td>
    <td>
      <a href="https://github.com/josh/ruby-coffee-script" title="Ruby CoffeeScript">
        CoffeeScript
      </a> y un
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        mecanismo para ejecutar javascript
      </a>
    </td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.coffee</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>coffee :index</tt></td>
  </tr>
</table>

### Plantillas Stylus

<table>
  <tr>
    <td>Dependencias</td>
    <td>
      <a href="https://github.com/forgecrafted/ruby-stylus" title="Ruby Stylus">
        Stylus
      </a> y un
      <a href="https://github.com/sstephenson/execjs/blob/master/README.md#readme" title="ExecJS">
        mecanismo para ejecutar javascript
      </a>
    </td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.styl</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>stylus :index</tt></td>
  </tr>
</table>

### Plantillas Yajl

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="https://github.com/brianmario/yajl-ruby" title="yajl-ruby">yajl-ruby</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.yajl</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
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

El contenido de la plantilla se evalúa como código Ruby, y la variable `json` es convertida a JSON mediante `#to_json`.

```ruby
json = { :foo => 'bar' }
json[:baz] = key
```

Las opciones `:callback` y `:variable` se pueden utilizar para decorar el objeto renderizado:

```ruby
var resource = {"foo":"bar","baz":"qux"}; present(resource);
```

### Plantillas WLang

<table>
  <tr>
    <td>Dependencias</td>
    <td><a href="https://github.com/blambeau/wlang/" title="wlang">wlang</a></td>
  </tr>
  <tr>
    <td>Extensiones de Archivo</td>
    <td><tt>.wlang</tt></td>
  </tr>
  <tr>
    <td>Ejemplo</td>
    <td><tt>wlang :index, :locals => { :clave => 'valor' }</tt></td>
  </tr>
</table>

Como no vas a poder llamar a métodos de Ruby (excepto por `yield`) desde una
plantilla WLang, casi siempre vas a querer pasarle locales.

### Plantillas Embebidas

```ruby
get '/' do
  haml '%div.titulo Hola Mundo'
end
```

Renderiza el template embebido en el string.

### Accediendo a Variables en Plantillas

Las plantillas son evaluadas dentro del mismo contexto que los manejadores de
ruta. Las variables de instancia asignadas en los manejadores de ruta son
accesibles directamente por las plantillas:

```ruby
get '/:id' do
  @foo = Foo.find(params['id'])
  haml '%h1= @foo.nombre'
end
```

O es posible especificar un Hash de variables locales explícitamente:

```ruby
get '/:id' do
  foo = Foo.find(params['id'])
  haml '%h1= bar.nombre', :locals => { :bar => foo }
end
```

Esto es usado típicamente cuando se renderizan plantillas como parciales desde
adentro de otras plantillas.

### Plantillas Inline

Las plantillas pueden ser definidas al final del archivo fuente:

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
%div.titulo Hola mundo!!!!!
```

NOTA: únicamente las plantillas inline definidas en el archivo fuente que
requiere Sinatra son cargadas automáticamente. Llamá `enable
:inline_templates` explícitamente si tenés plantillas inline en otros
archivos fuente.

### Plantillas Nombradas

Las plantillas también pueden ser definidas usando el método top-level
`template`:

```ruby
template :layout do
  "%html\n  =yield\n"
end

template :index do
  '%div.titulo Hola Mundo!'
end

get '/' do
  haml :index
end
```

Si existe una plantilla con el nombre "layout", va a ser usada cada vez que
una plantilla es renderizada. Podés desactivar los layouts individualmente
pasando `:layout => false` o globalmente con
`set :haml, :layout => false`:

```ruby
get '/' do
  haml :index, :layout => !request.xhr?
end
```

### Asociando Extensiones de Archivo

Para asociar una extensión de archivo con un motor de renderizado, usá
`Tilt.register`. Por ejemplo, si querés usar la extensión `tt` para
las plantillas Textile, podés hacer lo siguiente:

```ruby
Tilt.register :tt, Tilt[:textile]
```

### Agregando Tu Propio Motor de Renderizado

Primero, registrá tu motor con Tilt, y después, creá tu método de renderizado:

```ruby
Tilt.register :mipg, MiMotorParaPlantillaGenial

helpers do
  def mypg(*args) render(:mypg, *args) end
end

get '/' do
  mypg :index
end
```

Renderiza `./views/index.mypg`. Mirá https://github.com/rtomayko/tilt
para aprender más de Tilt.

## Filtros

Los filtros `before` son evaluados antes de cada petición dentro del mismo
contexto que las rutas. Pueden modificar la petición y la respuesta. Las
variables de instancia asignadas en los filtros son accesibles por las rutas y
las plantillas:

```ruby
before do
  @nota = 'Hey!'
  request.path_info = '/foo/bar/baz'
end

get '/foo/*' do
  @nota #=> 'Hey!'
  params['splat'] #=> 'bar/baz'
end
```

Los filtros `after` son evaluados después de cada petición dentro del mismo
contexto y también pueden modificar la petición y la respuesta. Las variables
de instancia asignadas en los filtros `before` y en las rutas son accesibles por
los filtros `after`:

```ruby
after do
  puts response.status
end
```

Nota: A menos que uses el método `body` en lugar de simplemente devolver un
string desde una ruta, el cuerpo de la respuesta no va a estar disponible en
un filtro after, debido a que todavía no se ha generado.

Los filtros aceptan un patrón opcional, que cuando está presente causa que los
mismos sean evaluados únicamente si el path de la petición coincide con ese
patrón:

```ruby
before '/protegido/*' do
  autenticar!
end

after '/crear/:slug' do |slug|
  session[:ultimo_slug] = slug
end
```

Al igual que las rutas, los filtros también pueden aceptar condiciones:

```ruby
before :agent => /Songbird/ do
  # ...
end

after '/blog/*', :host_name => 'ejemplo.com' do
  # ...
end
```

## Ayudantes

Usá el método top-level *helpers* para definir métodos ayudantes que
pueden ser utilizados dentro de los manejadores de rutas y las plantillas:

```ruby
helpers do
  def bar(nombre)
    "#{nombre}bar"
  end
end

get '/:nombre' do
  bar(params['nombre'])
end
```

Por cuestiones organizativas, puede resultar conveniente organizar los métodos
ayudantes en distintos módulos:

```ruby
module FooUtils
  def foo(nombre) "#{nombre}foo" end
end

module BarUtils
  def bar(nombre) "#{nombre}bar" end
end

helpers FooUtils, BarUtils
```

El efecto de utilizar *helpers* de esta manera es el mismo que resulta de
incluir los módulos en la clase de la aplicación.

### Usando Sesiones

Una sesión es usada para mantener el estado a través de distintas peticiones.
Cuando están activadas, proporciona un hash de sesión para cada sesión de usuario:

```ruby
enable :sessions

get '/' do
  "valor = " << session[:valor].inspect
end

get '/:valor' do
  session[:valor] = params['valor']
end
```

Tené en cuenta que `enable :sessions` guarda todos los datos en una
cookie, lo cual no es siempre deseable (guardar muchos datos va a incrementar
el tráfico, por citar un ejemplo). Podés usar cualquier middleware Rack para
manejar sesiones, de la misma manera que usarías cualquier otro middleware,
pero con la salvedad de que *no* tenés que llamar a `enable :sessions`:

```ruby
use Rack::Session::Pool, :expire_after => 2592000

get '/' do
  "valor = " << session[:valor].inspect
end

get '/:valor' do
  session[:valor] = params['valor']
end
```

Para incrementar la seguridad, los datos de la sesión almacenados en
la cookie son firmados con un secreto de sesión. Este secreto, es
generado aleatoriamente por Sinatra. De cualquier manera, hay que
tener en cuenta que cada vez que inicies la aplicación se va a generar
uno nuevo. Así, si querés que todas las instancias de tu aplicación
compartan un único secreto, tenés que definirlo vos:

```ruby
set :session_secret, 'super secreto'
```

Si necesitás una configuración más específica, `sessions` acepta un
Hash con opciones:

```ruby
set :sessions, :domain => 'foo.com'
```

### Interrupción

Para detener inmediatamente una petición dentro de un filtro o una ruta usá:

```ruby
halt
```

También podés especificar el estado:

```ruby
halt 410
```

O el cuerpo:

```ruby
halt 'esto va a ser el cuerpo'
```

O los dos:

```ruby
halt 401, 'salí de acá!'
```

Con cabeceras:

```ruby
halt 402, { 'Content-Type' => 'text/plain' }, 'venganza'
```

Obviamente, es posible utilizar `halt` con una plantilla:

```ruby
halt erb(:error)
```

### Paso

Una ruta puede pasarle el procesamiento a la siguiente ruta que coincida con
la petición usando `pass`:

```ruby
get '/adivina/:quien' do
  pass unless params['quien'] == 'Franco'
  'Adivinaste!'
end

get '/adivina/*' do
  'Erraste!'
end
```

Se sale inmediatamente del bloque de la ruta y se le pasa el control a la
siguiente ruta que coincida. Si no coincide ninguna ruta, se devuelve 404.

### Ejecutando Otra Ruta

Cuando querés obtener el resultado de la llamada a una ruta, `pass` no te va a
servir. Para lograr esto, podés usar `call`:

```ruby
get '/foo' do
  status, headers, body = call env.merge("PATH_INFO" => '/bar')
  [status, headers, body.map(&:upcase)]
end

get '/bar' do
  "bar"
end
```

Notá que en el ejemplo anterior, es conveniente mover `"bar"` a un
helper, y llamarlo desde `/foo` y `/bar`. Así, vas a simplificar
las pruebas y a mejorar el rendimiento.

Si querés que la petición se envíe a la misma instancia de la aplicación en
lugar de otra, usá `call!` en lugar de `call`.

En la especificación de Rack podés encontrar más información sobre
`call`.

### Asignando el Código de Estado, los Encabezados y el Cuerpo de una Respuesta

Es posible, y se recomienda, asignar el código de estado y el cuerpo de una
respuesta con el valor de retorno de una ruta. De cualquier manera, en varios
escenarios, puede que sea conveniente asignar el cuerpo en un punto arbitrario
del flujo de ejecución con el método `body`. A partir de ahí, podés usar ese
mismo método para acceder al cuerpo de la respuesta:

```ruby
get '/foo' do
  body "bar"
end

after do
  puts body
end
```

También es posible pasarle un bloque a `body`, que será ejecutado por el Rack
handler (podés usar esto para implementar streaming, mirá "Valores de retorno").

De manera similar, también podés asignar el código de estado y encabezados:

```ruby
get '/foo' do
  status 418
  headers \
    "Allow"   => "BREW, POST, GET, PROPFIND, WHEN",
    "Refresh" => "Refresh: 20; http://www.ietf.org/rfc/rfc2324.txt"
  body "I'm a tea pot!"
end
```

También, al igual que `body`, tanto `status` como `headers` pueden utilizarse
para obtener sus valores cuando no se les pasa argumentos.

### Streaming De Respuestas

A veces vas a querer empezar a enviar la respuesta a pesar de que todavía no
terminaste de generar su cuerpo. También es posible que, en algunos casos,
quieras seguir enviando información hasta que el cliente cierre la conexión.
Cuando esto ocurra, el helper `stream` te va a ser de gran ayuda:

```ruby
get '/' do
  stream do |out|
    out << "Esto va a ser legen -\n"
    sleep 0.5
    out << " (esperalo) \n"
    sleep 1
    out << "- dario!\n"
  end
end
```

Podés implementar APIs de streaming,
[Server-Sent Events](https://w3c.github.io/eventsource/) y puede ser usado
como base para [WebSockets](https://es.wikipedia.org/wiki/WebSockets). También
puede ser usado para incrementar el throughput si solo una parte del contenido
depende de un recurso lento.

Hay que tener en cuenta que el comportamiento del streaming, especialmente el
número de peticiones concurrentes, depende del servidor web utilizado para
alojar la aplicación. Puede que algunos servidores no soporten streaming
directamente, así el cuerpo de la respuesta será enviado completamente de una
vez cuando el bloque pasado a `stream` finalice su ejecución. Si estás usando
Shotgun, el streaming no va a funcionar.

Cuando se pasa `keep_open` como parámetro, no se va a enviar el mensaje
`close` al objeto de stream. Queda en vos cerrarlo en el punto de ejecución
que quieras. Nuevamente, hay que tener en cuenta que este comportamiento es
posible solo en servidores que soporten eventos, como Thin o Rainbows. El
resto de los servidores van a cerrar el stream de todos modos:

```ruby
set :server, :thin
conexiones = []

get '/' do
  # mantenemos abierto el stream
  stream(:keep_open) { |salida| conexiones << salida }
end

post '/' do
  # escribimos a todos los streams abiertos
  conexiones.each { |salida| salida << params['mensaje'] << "\n" }
  "mensaje enviado"
end
```

### Log (Registro)

En el ámbito de la petición, el helper `logger` (registrador) expone
una instancia de `Logger`:

```ruby
get '/' do
  logger.info "cargando datos"
  # ...
end
```

Este logger tiene en cuenta la configuración de logueo de tu Rack
handler. Si el logueo está desactivado, este método va a devolver un
objeto que se comporta como un logger pero que en realidad no hace
nada. Así, no vas a tener que preocuparte por esta situación.

Tené en cuenta que el logueo está habilitado por defecto únicamente
para `Sinatra::Application`. Si heredaste de
`Sinatra::Base`, probablemente quieras habilitarlo manualmente:

```ruby
class MiApp < Sinatra::Base
  configure :production, :development do
    enable :logging
  end
end
```

Para evitar que se inicialice cualquier middleware de logging, configurá
`logging` a `nil`. Tené en cuenta que, cuando hagas esto, `logger` va a
devolver `nil`. Un caso común es cuando querés usar tu propio logger. Sinatra
va a usar lo que encuentre en `env['rack.logger']`.

### Tipos Mime

Cuando usás `send_file` o archivos estáticos tal vez tengas tipos mime
que Sinatra no entiende. Usá `mime_type` para registrarlos a través de la
extensión de archivo:

```ruby
configure do
  mime_type :foo, 'text/foo'
end
```

También lo podés usar con el ayudante `content_type`:

```ruby
get '/' do
  content_type :foo
  "foo foo foo"
end
```

### Generando URLs

Para generar URLs deberías usar el método `url`. Por ejemplo, en Haml:

```ruby
%a{:href => url('/foo')} foo
```

Tiene en cuenta proxies inversos y encaminadores de Rack, si están presentes.

Este método también puede invocarse mediante su alias `to` (mirá un ejemplo
a continuación).

### Redirección del Navegador

Podés redireccionar al navegador con el método `redirect`:

```ruby
get '/foo' do
  redirect to('/bar')
end
```

Cualquier parámetro adicional se utiliza de la misma manera que los argumentos
pasados a `halt`:

```ruby
redirect to('/bar'), 303
redirect 'http://www.google.com/', 'te confundiste de lugar, compañero'
```

También podés redireccionar fácilmente de vuelta hacia la página desde donde
vino el usuario con `redirect back`:

```ruby
get '/foo' do
  "<a href='/bar'>hacer algo</a>"
end

get '/bar' do
  hacer_algo
  redirect back
end
```

Para pasar argumentos con una redirección, podés agregarlos a la cadena de
búsqueda:

```ruby
redirect to('/bar?suma=42')
```

O usar una sesión:

```ruby
enable :sessions

get '/foo' do
  session[:secreto] = 'foo'
  redirect to('/bar')
end

get '/bar' do
  session[:secreto]
end
```

### Cache Control

Asignar tus encabezados correctamente es el cimiento para realizar un cacheo
HTTP correcto.

Podés asignar el encabezado Cache-Control fácilmente:

```ruby
get '/' do
  cache_control :public
  "cachealo!"
end
```

Pro tip: configurar el cacheo en un filtro `before`:

```ruby
before do
  cache_control :public, :must_revalidate, :max_age => 60
end
```

Si estás usando el helper `expires` para definir el encabezado correspondiente,
`Cache-Control` se va a definir automáticamente:

```ruby
before do
  expires 500, :public, :must_revalidate
end
```

Para usar cachés adecuadamente, deberías considerar usar `etag` o
`last_modified`. Es recomendable que llames a estos asistentes *antes* de hacer
cualquier trabajo pesado, ya que van a enviar la respuesta inmediatamente si
el cliente ya tiene la versión actual en su caché:

```ruby
get '/articulo/:id' do
  @articulo = Articulo.find params['id']
  last_modified @articulo.updated_at
  etag @articulo.sha1
  erb :articulo
end
```

También es posible usar una
[weak ETag](https://en.wikipedia.org/wiki/HTTP_ETag#Strong_and_weak_validation):

```ruby
etag @articulo.sha1, :weak
```

Estos helpers no van a cachear nada por vos, sino que van a facilitar la
información necesaria para poder hacerlo. Si estás buscando soluciones rápidas
de cacheo con proxys reversos, mirá
[rack-cache](https://github.com/rtomayko/rack-cache):

```ruby
require "rack/cache"
require "sinatra"

use Rack::Cache

get '/' do
  cache_control :public, :max_age => 36000
  sleep 5
  "hola"
end
```

Usá la configuración `:static_cache_control` para agregar el encabezado
`Cache-Control` a archivos estáticos (ver la sección de configuración
para más detalles).

De acuerdo con la RFC 2616 tu aplicación debería comportarse diferente si a las
cabeceras If-Match o If-None-Match se le asigna el valor `*` cuando el
recurso solicitado ya existe. Sinatra asume para peticiones seguras (como get)
y potentes (como put) que el recurso existe, mientras que para el resto
(como post) asume que no. Podés cambiar este comportamiento con la opción
`:new_resource`:

```ruby
get '/crear' do
  etag '', :new_resource => true
  Articulo.create
  erb :nuevo_articulo
end
```

Si querés seguir usando una weak ETag, indicalo con la opción `:kind`:

```ruby
etag '', :new_resource => true, :kind => :weak
```

### Enviando Archivos

Para enviar archivos, podés usar el método `send_file`:

```ruby
get '/' do
  send_file 'foo.png'
end
```

Además acepta un par de opciones:

```ruby
send_file 'foo.png', :type => :jpg
```

Estas opciones son:

[filename]
  nombre del archivo devuelto, por defecto es el nombre real del archivo.

[last_modified]
  valor para el encabezado Last-Modified, por defecto toma el mtime del archivo.

[type]
  el content type que se va a utilizar, si no está presente se intenta adivinar
  a partir de la extensión del archivo.

[disposition]
  se utiliza para el encabezado Content-Disposition, y puede tomar alguno de los
  siguientes valores: `nil` (por defecto), `:attachment` e
  `:inline`

[length]
  encabezado Content-Length, por defecto toma el tamaño del archivo.

[status]
  código de estado devuelto. Resulta útil al enviar un archivo estático como una
  página de error.

Si el Rack handler lo soporta, se intentará no transmitir directamente desde el
proceso de Ruby. Si usás este método, Sinatra se va a encargar automáticamente de las
peticiones de rango.

### Accediendo al objeto de la petición

El objeto de la petición entrante puede ser accedido desde el nivel de la
petición (filtros, rutas y manejadores de errores) a través del método
`request`:

```ruby
# app corriendo en http://ejemplo.com/ejemplo
get '/foo' do
  t = %w[text/css text/html application/javascript]
  request.accept              # ['text/html', '*/*']
  request.accept? 'text/xml'  # true
  request.preferred_type(t)   # 'text/html'
  request.body                # cuerpo de la petición enviado por el cliente (ver más abajo)
  request.scheme              # "http"
  request.script_name         # "/ejemplo"
  request.path_info           # "/foo"
  request.port                # 80
  request.request_method      # "GET"
  request.query_string        # ""
  request.content_length      # longitud de request.body
  request.media_type          # tipo de medio de request.body
  request.host                # "ejemplo.com"
  request.get?                # true (hay métodos análogos para los otros verbos)
  request.form_data?          # false
  request["UNA_CABECERA"]     # valor de la cabecera UNA_CABECERA
  request.referrer            # la referencia del cliente o '/'
  request.user_agent          # user agent (usado por la condición :agent)
  request.cookies             # hash de las cookies del navegador
  request.xhr?                # es una petición ajax?
  request.url                 # "http://ejemplo.com/ejemplo/foo"
  request.path                # "/ejemplo/foo"
  request.ip                  # dirección IP del cliente
  request.secure?             # false (sería true sobre ssl)
  request.forwarded?          # true (si se está corriendo atrás de un proxy reverso)
  requuest.env                # hash de entorno directamente entregado por Rack
end
```

Algunas opciones, como `script_name` o `path_info` pueden
también ser escritas:

```ruby
before { request.path_info = "/" }

get "/" do
  "todas las peticiones llegan acá"
end
```

El objeto `request.body` es una instancia de IO o StringIO:

```ruby
post "/api" do
  request.body.rewind  # en caso de que alguien ya lo haya leído
  datos = JSON.parse request.body.read
  "Hola #{datos['nombre']}!"
end
```

### Archivos Adjuntos

Podés usar el helper `attachment` para indicarle al navegador que
almacene la respuesta en el disco en lugar de mostrarla en pantalla:

```ruby
get '/' do
  attachment
  "guardalo!"
end
```

También podés pasarle un nombre de archivo:

```ruby
get '/' do
  attachment "info.txt"
  "guardalo!"
end
```

### Fecha y Hora

Sinatra pone a tu disposición el helper `time_for`, que genera un objeto `Time`
a partir del valor que recibe como argumento. Este valor puede ser un
`String`, pero también es capaz de convertir objetos `DateTime`, `Date` y de
otras clases similares:

```ruby
get '/' do
  pass if Time.now > time_for('Dec 23, 2012')
  "todavía hay tiempo"
end
```

Este método es usado internamente por métodos como `expires` y `last_modified`,
entre otros. Por lo tanto, es posible extender el comportamiento de estos
métodos sobreescribiendo `time_for` en tu aplicación:

```ruby
helpers do
  def time_for(value)
    case value
    when :ayer then Time.now - 24*60*60
    when :mañana then Time.now + 24*60*60
    else super
    end
  end
end

get '/' do
  last_modified :ayer
  expires :mañana
  "hola"
end
```

### Buscando los Archivos de las Plantillas

El helper `find_template` se utiliza para encontrar los archivos de las
plantillas que se van a renderizar:

```ruby
find_template settings.views, 'foo', Tilt[:haml] do |archivo|
  puts "podría ser #{archivo}"
end
```

Si bien esto no es muy útil, lo interesante es que podés sobreescribir este
método, y así enganchar tu propio mecanismo de búsqueda. Por ejemplo, para
poder utilizar más de un directorio de vistas:

```ruby
set :views, ['vistas', 'plantillas']

helpers do
  def find_template(views, name, engine, &block)
    Array(views).each { |v| super(v, name, engine, &block) }
  end
end
```

Otro ejemplo consiste en usar directorios diferentes para los distintos motores
de renderizado:

```ruby
set :views, :sass => 'vistas/sass', :haml => 'plantillas', :defecto => 'vistas'

helpers do
  def find_template(views, name, engine, &block)
    _, folder = views.detect { |k,v| engine == Tilt[k] }
    folder ||= views[:defecto]
    super(folder, name, engine, &block)
  end
end
```

¡Es muy fácil convertir estos ejemplos en una extensión y compartirla!

Notá que `find_template` no verifica si un archivo existe realmente, sino
que llama al bloque que recibe para cada path posible. Esto no representa un
problema de rendimiento debido a que `render` va a usar `break` ni bien
encuentre un archivo que exista. Además, las ubicaciones de las plantillas (y
su contenido) se cachean cuando no estás en el modo de desarrollo. Es bueno
tener en cuenta lo anterior si escribís un método extraño.

## Configuración

Ejecutar una vez, en el inicio, en cualquier entorno:

```ruby
configure do
  # asignando una opción
  set :opcion, 'valor'

  # asignando varias opciones
  set :a => 1, :b => 2

  # atajo para `set :opcion, true`
  enable :opcion

  # atajo para `set :opcion, false`
  disable :opcion

  # también podés tener configuraciones dinámicas usando bloques
  set(:css_dir) { File.join(views, 'css') }
end
```

Ejecutar únicamente cuando el entorno (la variable de entorno RACK_ENV) es
`:production`:

```ruby
configure :production do
  ...
end
```

Ejecutar cuando el entorno es `:production` o `:test`:

```ruby
configure :production, :test do
  ...
end
```

Podés acceder a estas opciones utilizando el método `settings`:

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

### Configurando la Protección de Ataques

Sinatra usa [Rack::Protection](https://github.com/sinatra/rack-protection#readme)
para defender a tu aplicación de los ataques más comunes. Si por algún motivo,
querés desactivar esta funcionalidad, podés hacerlo como se indica a
continuación (ten en cuenta que tu aplicación va a quedar expuesta a un
montón de vulnerabilidades bien conocidas):

```ruby
disable :protection
```

También es posible desactivar una única capa de defensa:

```ruby
set :protection, :except => :path_traversal
```

O varias:

```ruby
set :protection, :except => [:path_traversal, :session_hijacking]
```

### Configuraciones Disponibles

<dl>
  <dt>absolute_redirects</dt>
  <dd>
    Si está deshabilitada, Sinatra va a permitir
    redirecciones relativas, sin embargo, como consecuencia
    de esto, va a dejar de cumplir con el RFC 2616 (HTTP
    1.1), que solamente permite redirecciones absolutas.

    Activalo si tu apliación está corriendo atrás de un proxy
    reverso que no se ha configurado adecuadamente. Notá que
    el helper <tt>url</tt> va a seguir produciendo URLs absolutas, a
    menos que le pasés <tt>false</tt> como segundo parámetro.

    Deshabilitada por defecto.
  </dd>

  <dt>add_charset</dt>
  <dd>
    Tipos mime a los que el helper <tt>content_type</tt> les
    añade automáticamente el charset.

    En general, no deberías asignar directamente esta opción,
    sino añadirle los charsets que quieras:
    <tt>settings.add_charset &lt;&lt; "application/foobar"</tt>
  </dd>

  <dt>app_file</dt>
  <dd>
    Path del archivo principal de la aplicación, se utiliza
    para detectar la raíz del proyecto, el directorio de las
    vistas y el público, así como las plantillas inline.
  </dd>

  <dt>bind</dt>
  <dd>
    Dirección IP que utilizará el servidor integrado (por
    defecto: 0.0.0.0).
  </dd>

  <dt>default_encoding</dt>
  <dd>
    Encoding utilizado cuando el mismo se desconoce (por
    defecto <tt>"utf-8"</tt>).
  </dd>

  <dt>dump_errors</dt>
  <dd>
    Mostrar errores en el log.
  </dd>

  <dt>environment</dt>
  <dd>
    Entorno actual, por defecto toma el valor de
    <tt>ENV['RACK_ENV']</tt>, o <tt>"development"</tt> si no
    está disponible.
  </dd>

  <dt>logging</dt>
  <dd>
    Define si se utiliza el logger.
  </dd>

  <dt>lock</dt>
  <dd>
    Coloca un lock alrededor de cada petición, procesando
    solamente una por proceso.

    Habilitá esta opción si tu aplicación no es thread-safe.
    Se encuentra deshabilitada por defecto.
  </dd>

  <dt>method_override</dt>
  <dd>
    Utiliza el parámetro <tt>_method</tt> para permtir
    formularios put/delete en navegadores que no los
    soportan.
  </dd>

  <dt>port</dt>
  <dd>
    Puerto en el que escuchará el servidor integrado.
  </dd>

  <dt>prefixed_redirects</dt>
  <dd>
    Define si inserta <tt>request.script_name</tt> en las
    redirecciones cuando no se proporciona un path absoluto.
    De esta manera, cuando está habilitada,
    <tt>redirect '/foo'</tt> se comporta de la misma manera
    que <tt>redirect to('/foo')</tt>. Se encuentra
    deshabilitada por defecto.
  </dd>

  <dt>protection</dt>
  <dd>
    Define si deben activarse las protecciones para los
    ataques web más comunes. Para más detalles mirá la
    sección sobre la configuración de protección de ataques
    más arriba.
  </dd>

  <dt>public_dir</dt>
  <dd>
    Alias para <tt>public_folder</tt>, que se encuentra a
    continuación.
  </dd>

  <dt>public_folder</dt>
  <dd>
    Lugar del directorio desde donde se sirven los archivos
    públicos. Solo se utiliza cuando se sirven archivos
    estáticos (ver la opción <tt>static</tt>). Si no
    está presente, se infiere del valor de la opción
    <tt>app_file</tt>.
  </dd>

  <dt>reload_templates</dt>
  <dd>
    Define si se recargan las plantillas entre peticiones.

    Se encuentra activado en el entorno de desarrollo.
  </dd>

  <dt>root</dt>
  <dd>
    Lugar del directorio raíz del proyecto. Si no está
    presente, se infiere del valor de la opción
    <tt>app_file</tt>.
  </dd>

  <dt>raise_errors</dt>
  <dd>
    Elevar excepciones (detiene la aplicación). Se
    encuentra activada por defecto cuando el valor de
    <tt>environment</tt>  es <tt>"test"</tt>. En caso
    contrario estará desactivada.
  </dd>

  <dt>run</dt>
  <dd>
    Cuando está habilitada, Sinatra se va a encargar de
    iniciar el servidor web, no la habilites cuando estés
    usando rackup o algún otro medio.
  </dd>

  <dt>running</dt>
  <dd>
    Indica si el servidor integrado está ejecutándose, ¡no
    cambiés esta configuración!.
  </dd>

  <dt>server</dt>
  <dd>
    Servidor, o lista de servidores, para usar como servidor
    integrado. Por defecto: <tt>['thin', 'mongrel', 'webrick']</tt>,
    el orden establece la prioridad.
  </dd>

  <dt>sessions</dt>
  <dd>
    Habilita el soporte de sesiones basadas en cookies a
    través de <tt>Rack::Session::Cookie</tt>. Ver la
    sección 'Usando Sesiones' para más información.
  </dd>

  <dt>show_exceptions</dt>
  <dd>
    Muestra un stack trace en el navegador cuando ocurre una
    excepción. Se encuentra activada por defecto cuando el
    valor de <tt>environment</tt> es <tt>"development"</tt>.
    En caso contrario estará desactivada.
  </dd>

  <dt>static</dt>
  <dd>
    Define si Sinatra debe encargarse de servir archivos
    estáticos.

    Deshabilitala cuando uses un servidor capaz de
    hacerlo por sí solo, porque mejorará el
    rendimiento. Se encuentra habilitada por
    defecto en el estilo clásico y desactivado en el
    el modular.
  </dd>

  <dt>static_cache_control</dt>
  <dd>
    Cuando Sinatra está sirviendo archivos estáticos, y
    esta opción está habilitada, les va a agregar encabezados
    <tt>Cache-Control</tt> a las respuestas. Para esto
    utiliza el helper <tt>cache_control</tt>. Se encuentra
    deshabilitada por defecto. Notar que es necesario
    utilizar un array cuando se asignan múltiples valores:
    <tt>set :static_cache_control, [:public, :max_age => 300]</tt>.
  </dd>

  <dt>views</dt>
  <dd>
    Path del directorio de las vistas. Si no está presente,
    se infiere del valor de la opción <tt>app_file</tt>.
  </dd>
</dl>

## Entornos

Existen tres entornos (`environments`) predefinidos: `development`,
`production` y `test`. El entorno por defecto es
`development` y tiene algunas particularidades:

* Se recargan las plantillas entre una petición y la siguiente, a diferencia
de `production` y `test`, donde se cachean.
* Se instalan manejadores de errores `not_found` y `error`
especiales que muestran un stack trace en el navegador cuando son disparados.

Para utilizar alguno de los otros entornos puede asignarse el valor
correspondiente a la variable de entorno `RACK_ENV`, o bien utilizar la opción
`-e` al ejecutar la aplicación:

```shell
ruby mi_app.rb -e <ENTORNO>
```

Los métodos `development?`, `test?` y `production?` te permiten conocer el
entorno actual.

## Manejo de Errores

Los manejadores de errores se ejecutan dentro del mismo contexto que las rutas
y los filtros `before`, lo que significa que podés usar, por ejemplo,
`haml`, `erb`, `halt`, etc.

### No encontrado <em>(Not Found)</em>

Cuando se eleva una excepción `Sinatra::NotFound`, o el código de
estado de la respuesta es 404, el manejador `not_found` es invocado:

```ruby
not_found do
  'No existo'
end
```

### Error

El manejador `error` es invocado cada vez que una excepción es elevada
desde un bloque de ruta o un filtro. El objeto de la excepción se puede
obtener de la variable Rack `sinatra.error`:

```ruby
error do
  'Disculpá, ocurrió un error horrible - ' + env['sinatra.error'].message
end
```

Errores personalizados:

```ruby
error MiErrorPersonalizado do
  'Lo que pasó fue...' + env['sinatra.error'].message
end
```

Entonces, si pasa esto:

```ruby
get '/' do
  raise MiErrorPersonalizado, 'algo malo'
end
```

Obtenés esto:

  Lo que pasó fue... algo malo

También, podés instalar un manejador de errores para un código de estado:

```ruby
error 403 do
  'Acceso prohibido'
end

get '/secreto' do
  403
end
```

O un rango:

```ruby
error 400..510 do
  'Boom'
end
```

Sinatra instala manejadores `not_found` y `error` especiales
cuando se ejecuta dentro del entorno de desarrollo "development".

## Rack Middleware

Sinatra corre sobre [Rack](http://rack.github.io/), una interfaz minimalista
que es un estándar para frameworks webs escritos en Ruby. Una de las
características más interesantes de Rack para los desarrolladores de aplicaciones
es el soporte de "middleware" -- componentes que se ubican entre el servidor y
tu aplicación, supervisando y/o manipulando la petición/respuesta HTTP para
proporcionar varios tipos de funcionalidades comunes.

Sinatra hace muy sencillo construir tuberías de Rack middleware a través del
método top-level `use`:

```ruby
require 'sinatra'
require 'mi_middleware_personalizado'

use Rack::Lint
use MiMiddlewarePersonalizado

get '/hola' do
  'Hola Mundo'
end
```

La semántica de `use` es idéntica a la definida para el DSL
Rack::Builder[http://www.rubydoc.info/github/rack/rack/master/Rack/Builder] (más
frecuentemente usado en archivos rackup). Por ejemplo, el método `use`
acepta argumentos múltiples/variables así como bloques:

```ruby
use Rack::Auth::Basic do |nombre_de_usuario, password|
  nombre_de_usuario == 'admin' && password == 'secreto'
end
```

Rack es distribuido con una variedad de middleware estándar para logging,
debugging, enrutamiento URL, autenticación y manejo de sesiones. Sinatra
usa muchos de estos componentes automáticamente de acuerdo a su configuración
para que usualmente no tengas que usarlas (con `use`) explícitamente.

Podés encontrar middleware útil en
[rack](https://github.com/rack/rack/tree/master/lib/rack),
[rack-contrib](https://github.com/rack/rack-contrib#readme),
o en la [Rack wiki](https://github.com/rack/rack/wiki/List-of-Middleware).

## Pruebas

Las pruebas para las aplicaciones Sinatra pueden ser escritas utilizando
cualquier framework o librería de pruebas basada en Rack. Se recomienda usar
[Rack::Test](http://www.rubydoc.info/github/brynary/rack-test/master/frames):

```ruby
require 'mi_app_sinatra'
require 'minitest/autorun'
require 'rack/test'

class MiAppTest < Minitest::Test
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def test_mi_defecto
    get '/'
    assert_equal 'Hola Mundo!', last_response.body
  end

  def test_con_parametros
    get '/saludar', :name => 'Franco'
    assert_equal 'Hola Frank!', last_response.body
  end

  def test_con_entorno_rack
    get '/', {}, 'HTTP_USER_AGENT' => 'Songbird'
    assert_equal "Estás usando Songbird!", last_response.body
  end
end
```

## Sinatra::Base - Middleware, Librerías, y Aplicaciones Modulares

Definir tu aplicación en el nivel superior funciona bien para micro-aplicaciones
pero trae inconvenientes considerables a la hora de construir componentes
reutilizables como Rack middleware, Rails metal, librerías simples con un
componente de servidor o incluso extensiones de Sinatra. El DSL de alto nivel
asume una configuración apropiada para micro-aplicaciones (por ejemplo, un
único archivo de aplicación, los directorios `./public` y
`./views`, logging, página con detalles de excepción, etc.). Ahí es
donde `Sinatra::Base` entra en el juego:

```ruby
require 'sinatra/base'

class MiApp < Sinatra::Base
  set :sessions, true
  set :foo, 'bar'

  get '/' do
    'Hola Mundo!'
  end
end
```

Las subclases de `Sinatra::Base` tienen disponibles exactamente los
mismos métodos que los provistos por el DSL de top-level. La mayoría de las
aplicaciones top-level se pueden convertir en componentes
`Sinatra::Base` con dos modificaciones:

* Tu archivo debe requerir `sinatra/base` en lugar de `sinatra`; de otra
  manera, todos los métodos del DSL de sinatra son importados dentro del
  espacio de nombres principal.
* Poné las rutas, manejadores de errores, filtros y opciones de tu aplicación
  en una subclase de `Sinatra::Base`.

`Sinatra::Base` es una pizarra en blanco. La mayoría de las opciones están
desactivadas por defecto, incluyendo el servidor incorporado. Mirá
[Opciones y Configuraciones](http://www.sinatrarb.com/configuration.html)
para detalles sobre las opciones disponibles y su comportamiento.

### Estilo Modular vs. Clásico

Contrariamente a la creencia popular, no hay nada de malo con el estilo clásico.
Si se ajusta a tu aplicación, no es necesario que la cambies a una modular.

La desventaja de usar el estilo clásico en lugar del modular consiste en que
solamente podés tener una aplicación Sinatra por proceso Ruby. Si tenés
planificado usar más, cambiá al estilo modular. Al mismo tiempo, ten en
cuenta que no hay ninguna razón por la cuál no puedas mezclar los estilos
clásico y modular.

A continuación se detallan las diferencias (sútiles) entre las configuraciones
de ambos estilos:

<table>
  <tr>
    <td>Configuración</td>
    <td>Clásica</td>
    <td>Modular</td>
  </tr>

  <tr>
    <td>app_file</td>
    <td>archivo que carga sinatra</td>
    <td>archivo con la subclase de Sinatra::Base</td>
  </tr>

  <tr>
    <td>run</td>
    <td>$0 == app_file</td>
    <td>false</td>
  </tr>

  <tr>
    <td>logging</td>
    <td>true</td>
    <td>false</td>
  </tr>

  <tr>
    <td>method_override</td>
    <td>true</td>
    <td>false</td>
  </tr>

  <tr>
    <td>inline_templates</td>
    <td>true</td>
    <td>false</td>
  </tr>

  <tr>
    <td>static</td>
    <td>true</td>
    <td>File.exist?(public_folder)</td>
  </tr>
</table>

### Sirviendo una Aplicación Modular

Las dos opciones más comunes para iniciar una aplicación modular son, iniciarla
activamente con `run!`:

```ruby
# mi_app.rb
require 'sinatra/base'

class MiApp < Sinatra::Base
  # ... código de la app  ...

  # iniciar el servidor si el archivo fue ejecutado directamente
  run! if app_file == $0
end
```

Iniciar con:

```shell
ruby mi_app.rb
```

O, con un archivo `config.ru`, que permite usar cualquier handler Rack:

```ruby
# config.ru
require './mi_app'
run MiApp
```

Después ejecutar:

```shell
rackup -p 4567
```

### Usando una Aplicación Clásica con un Archivo config.ru

Escribí el archivo de tu aplicación:

```ruby
# app.rb
require 'sinatra'

get '/' do
  'Hola mundo!'
end
```

Y el `config.ru` correspondiente:

```ruby
require './app'
run Sinatra::Application
```

### ¿Cuándo usar config.ru?

Indicadores de que probablemente querés usar `config.ru`:

* Querés realizar el deploy con un handler Rack distinto (Passenger, Unicorn,
  Heroku, ...).
* Querés usar más de una subclase de `Sinatra::Base`.
* Querés usar Sinatra únicamente para middleware, pero no como un endpoint.

<b>No hay necesidad de utilizar un archivo `config.ru` exclusivamente
porque tenés una aplicación modular, y no necesitás una aplicación modular para
iniciarla con `config.ru`.</b>

### Utilizando Sinatra como Middleware

Sinatra no solo es capaz de usar otro Rack middleware, sino que a su vez,
cualquier aplicación Sinatra puede ser agregada delante de un endpoint Rack
como middleware. Este endpoint puede ser otra aplicación Sinatra, o cualquier
aplicación basada en Rack (Rails/Ramaze/Camping/...):

```ruby
require 'sinatra/base'

class PantallaDeLogin < Sinatra::Base
  enable :sessions

  get('/login') { haml :login }

  post('/login') do
    if params['nombre'] == 'admin' && params['password'] == 'admin'
      session['nombre_de_usuario'] = params['nombre']
    else
      redirect '/login'
    end
  end
end

class MiApp < Sinatra::Base
  # el middleware se ejecutará antes que los filtros
  use PantallaDeLogin

  before do
    unless session['nombre_de_usuario']
      halt "Acceso denegado, por favor <a href='/login'>iniciá sesión</a>."
    end
  end

  get('/') { "Hola #{session['nombre_de_usuario']}." }
end
```

### Creación Dinámica de Aplicaciones

Puede que en algunas ocasiones quieras crear nuevas aplicaciones en
tiempo de ejecución sin tener que asignarlas a una constante. Para
esto tenés `Sinatra.new`:

```ruby
require 'sinatra/base'
mi_app = Sinatra.new { get('/') { "hola" } }
mi_app.run!
```

Acepta como argumento opcional una aplicación desde la que se
heredará:

```ruby
# config.ru
require 'sinatra/base'

controller = Sinatra.new do
  enable :logging
  helpers MisHelpers
end

map('/a') do
  run Sinatra.new(controller) { get('/') { 'a' } }
end

map('/b') do
  run Sinatra.new(controller) { get('/') { 'b' } }
end
```

Construir aplicaciones de esta forma resulta especialmente útil para
testear extensiones Sinatra o para usar Sinatra en tus librerías.

Por otro lado, hace extremadamente sencillo usar Sinatra como
middleware:

```ruby
require 'sinatra/base'

use Sinatra do
  get('/') { ... }
end

run ProyectoRails::Application
```

## Ámbitos y Ligaduras

El ámbito en el que te encontrás determina que métodos y variables están
disponibles.

### Ámbito de Aplicación/Clase

Cada aplicación Sinatra es una subclase de `Sinatra::Base`. Si estás
usando el DSL de top-level (`require 'sinatra'`), entonces esta clase es
`Sinatra::Application`, de otra manera es la subclase que creaste
explícitamente. Al nivel de la clase tenés métodos como `get` o `before`, pero
no podés acceder a los objetos `request` o `session`, ya que hay una única
clase de la aplicación para todas las peticiones.

Las opciones creadas utilizando `set` son métodos al nivel de la clase:

```ruby
class MiApp < Sinatra::Base
  # Ey, estoy en el ámbito de la aplicación!
  set :foo, 42
  foo # => 42

  get '/foo' do
    # Hey, ya no estoy en el ámbito de la aplicación!
  end
end
```

Tenés la ligadura al ámbito de la aplicación dentro de:

* El cuerpo de la clase de tu aplicación
* Métodos definidos por extensiones
* El bloque pasado a `helpers`
* Procs/bloques usados como el valor para `set`

Este ámbito puede alcanzarse de las siguientes maneras:

* A través del objeto pasado a los bloques de configuración (`configure { |c| ...}`)
* Llamando a `settings` desde dentro del ámbito de la petición

### Ámbito de Petición/Instancia

Para cada petición entrante, una nueva instancia de la clase de tu aplicación
es creada y todos los bloques de rutas son ejecutados en ese ámbito. Desde este
ámbito podés acceder a los objetos `request` y `session` o llamar a los métodos
de renderización como `erb` o `haml`. Podés acceder al ámbito de la aplicación
desde el ámbito de la petición utilizando `settings`:

```ruby
class MiApp < Sinatra::Base
  # Ey, estoy en el ámbito de la aplicación!
  get '/definir_ruta/:nombre' do
    # Ámbito de petición para '/definir_ruta/:nombre'
    @valor = 42

    settings.get("/#{params['nombre']}") do
      # Ámbito de petición para "/#{params['nombre']}"
      @valor # => nil (no es la misma petición)
    end

    "Ruta definida!"
  end
end
```

Tenés la ligadura al ámbito de la petición dentro de:

* bloques pasados a get/head/post/put/delete/options
* filtros before/after
* métodos ayudantes
* plantillas/vistas

### Ámbito de Delegación

El ámbito de delegación solo reenvía métodos al ámbito de clase. De cualquier
manera, no se comporta 100% como el ámbito de clase porque no tenés la ligadura
de la clase: únicamente métodos marcados explícitamente para delegación están
disponibles y no compartís variables/estado con el ámbito de clase (léase:
tenés un `self` diferente). Podés agregar delegaciones de método llamando a
`Sinatra::Delegator.delegate :nombre_del_metodo`.

Tenés la ligadura al ámbito de delegación dentro de:

* La ligadura del top-level, si hiciste `require "sinatra"`
* Un objeto extendido con el mixin `Sinatra::Delegator`

Hechale un vistazo al código: acá está el
[Sinatra::Delegator mixin](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/base.rb#L1609-1633)
que [extiende el objeto main](https://github.com/sinatra/sinatra/blob/ca06364/lib/sinatra/main.rb#L28-30).

## Línea de Comandos

Las aplicaciones Sinatra pueden ser ejecutadas directamente:

```shell
ruby miapp.rb [-h] [-x] [-e ENTORNO] [-p PUERTO] [-o HOST] [-s MANEJADOR]
```

Las opciones son:

```
-h # ayuda
-p # asigna el puerto (4567 es usado por defecto)
-o # asigna el host (0.0.0.0 es usado por defecto)
-e # asigna el entorno (development es usado por defecto)
-s # especifica el servidor/manejador rack (thin es usado por defecto)
-x # activa el mutex lock (está desactivado por defecto)
```

### Multi-threading

_Basado en [esta respuesta en StackOverflow][so-answer] escrita por Konstantin_

Sinatra no impone ningún modelo de concurrencia, sino que lo deja en manos del
handler Rack que se esté usando (Thin, Puma, WEBrick). Sinatra en sí mismo es
thread-safe, así que no hay problema en que el Rack handler use un modelo de
concurrencia basado en hilos.

Esto significa que, cuando estemos arrancando el servidor, tendríamos que
especificar la opción adecuada para el handler Rack específico. En este ejemplo
vemos cómo arrancar un servidor Thin multihilo:

```ruby
# app.rb

require 'sinatra/base'

class App < Sinatra::Base
  get '/' do
    "¡Hola, Mundo!"
  end
end

App.run!
```

Para arrancar el servidor, el comando sería:

```shell
thin --threaded start
```

[so-answer]: http://stackoverflow.com/questions/6278817/is-sinatra-multi-threaded/6282999#6282999)

## Versiones de Ruby Soportadas

Las siguientes versiones de Ruby son soportadas oficialmente:

<dl>
  <dt>Ruby 1.8.7</dt>
  <dd>
    1.8.7 es soportado completamente. Sin embargo, si no hay nada que te lo
    prohiba, te recomendamos que uses 1.9.2 o cambies a JRuby o Rubinius. No se
    dejará de dar soporte a 1.8.7 hasta Sinatra 2.0 y Ruby 2.0, aunque si se
    libera la versión 1.8.8 de Ruby las cosas podrían llegar a cambiar. Sin
    embargo, que eso ocurra es muy poco probable, e incluso el caso de que lo
    haga, puede que se siga dando soporte a 1.8.7. <b>Hemos dejado de soportar
    Ruby 1.8.6.</b> Si querés ejecutar Sinatra sobre 1.8.6, podés utilizar la
    versión 1.2, pero ten en cuenta que una vez que Sinatra 1.4.0 sea liberado,
    ya no se corregirán errores por más que se reciban reportes de los mismos.
  </dd>

  <dt>Ruby 1.9.2</dt>
  <dd>
    1.9.2 es soportado y recomendado. No uses 1.9.2p0, porque se producen fallos
    de segmentación cuando se ejecuta Sinatra. El soporte se mantendrá al menos
    hasta que se libere la versión 1.9.4/2.0 de Ruby. El soporte para la última
    versión de la serie 1.9 se mantendrá mientras lo haga el equipo principal de Ruby.
  </dd>

  <dt>Ruby 1.9.3</dt>
  <dd>
    1.9.3 es soportado y recomendado. Ten en cuenta que el cambio a 1.9.3 desde
    una versión anterior va a invalidar todas las sesiones.
  </dd>

  <dt>Rubinius</dt>
  <dd>
    Rubinius es soportado oficialmente (Rubinius >= 1.2.4). Todo funciona
    correctamente, incluyendo los lenguajes de plantillas. La próxima versión,
    2.0, también es soportada, incluyendo el modo 1.9.
  </dd>

  <dt>JRuby</dt>
  <dd>
    JRuby es soportado oficialmente (JRuby >= 1.6.7). No se conocen problemas
    con librerías de plantillas de terceras partes. Sin embargo, si elegís usar
    JRuby, deberías examinar sus Rack handlers porque el servidor web Thin no es
    soportado completamente. El soporte de JRuby para extensiones C se encuentra
    en una etapa experimental, sin embargo, de momento, solamente RDiscount,
    Redcarpet, RedCloth y Yajl, así como Thin y Mongrel se ven afectadas.
  </dd>
</dl>

Siempre le prestamos atención a las nuevas versiones de Ruby.

Las siguientes implementaciones de Ruby no se encuentran soportadas
oficialmente. De cualquier manera, pueden ejecutar Sinatra:

* Versiones anteriores de JRuby y Rubinius
* Ruby Enterprise Edition
* MacRuby, Maglev e IronRuby
* Ruby 1.9.0 y 1.9.1 (pero no te recomendamos que los uses)

No ser soportada oficialmente, significa que si las cosas se rompen
ahí y no en una plataforma soportada, asumimos que no es nuestro problema sino
el suyo.

Nuestro servidor CI también se ejecuta sobre ruby-head (que será la próxima
versión 2.1.0) y la rama 1.9.4. Como están en movimiento constante, no podemos
garantizar nada. De todas formas, podés contar con que tanto 1.9.4-p0 como
2.1.0-p0 sea soportadas.

Sinatra debería funcionar en cualquier sistema operativo soportado por la
implementación de Ruby elegida.

En este momento, no vas a poder ejecutar Sinatra en Cardinal, SmallRuby,
BlueRuby o cualquier versión de Ruby anterior a 1.8.7.

## A la Vanguardia

Si querés usar el código de Sinatra más reciente, sentite libre de ejecutar
tu aplicación sobre la rama master, en general es bastante estable.

También liberamos prereleases de vez en cuando, así, podés hacer:

```shell
gem install sinatra --pre
```

Para obtener algunas de las últimas características.

### Con Bundler

Esta es la manera recomendada para ejecutar tu aplicación sobre la última
versión de Sinatra usando [Bundler](http://bundler.io).

Primero, instalá Bundler si no lo hiciste todavía:

```shell
gem install bundler
```

Después, en el directorio de tu proyecto, creá un archivo `Gemfile`:

```ruby
source :rubygems
gem 'sinatra', :git => "git://github.com/sinatra/sinatra.git"

# otras dependencias
gem 'haml'                    # por ejemplo, si usás haml
gem 'activerecord', '~> 3.0'  # quizás también necesités ActiveRecord 3.x
```

Tené en cuenta que tenés que listar todas las dependencias directas de tu
aplicación. No es necesario listar las dependencias de Sinatra (Rack y Tilt)
porque Bundler las agrega directamente.

Ahora podés arrancar tu aplicación así:

```shell
bundle exec ruby miapp.rb
```

### Con Git

Cloná el repositorio localmente y ejecutá tu aplicación, asegurándote que el
directorio `sinatra/lib` esté en el `$LOAD_PATH`:

```shell
cd miapp
git clone git://github.com/sinatra/sinatra.git
ruby -Isinatra/lib miapp.rb
```

Para actualizar el código fuente de Sinatra en el futuro:

```shell
cd miapp/sinatra
git pull
```

### Instalación Global

Podés construir la gem vos mismo:

```shell
git clone git://github.com/sinatra/sinatra.git
cd sinatra
rake sinatra.gemspec
rake install
```

Si instalás tus gems como root, el último paso debería ser

```shell
sudo rake install
```

## Versionado

Sinatra utiliza el [Versionado Semántico](http://semver.org/),
siguiendo las especificaciones SemVer y SemVerTag.

## Lecturas Recomendadas

* [Sito web del proyecto](http://www.sinatrarb.com/) - Documentación
  adicional, noticias, y enlaces a otros recursos.
* [Contribuyendo](http://www.sinatrarb.com/contributing) - ¿Encontraste un
  error?. ¿Necesitás ayuda?. ¿Tenés un parche?.
* [Seguimiento de problemas](https://github.com/sinatra/sinatra/issues)
* [Twitter](https://twitter.com/sinatra)
* [Lista de Correo](http://groups.google.com/group/sinatrarb/topics)
* [IRC: #sinatra](irc://chat.freenode.net/#sinatra) en http://freenode.net
* [Sinatra Book](https://github.com/sinatra/sinatra-book/) Tutorial (en inglés).
* [Sinatra Recipes](http://recipes.sinatrarb.com/) Recetas contribuidas
  por la comunidad (en inglés).
* Documentación de la API para la
  [última versión liberada](http://www.rubydoc.info/gems/sinatra) o para la
  [rama de desarrollo actual](http://www.rubydoc.info/github/sinatra/sinatra)
  en http://www.rubydoc.info/
* [Servidor de CI](https://travis-ci.org/sinatra/sinatra)
