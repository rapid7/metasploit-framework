/*
	Copyright (c) 2004-2006, The Dojo Foundation
	All Rights Reserved.

	Licensed under the Academic Free License version 2.1 or above OR the
	modified BSD license. For more information on Dojo licensing, see:

		http://dojotoolkit.org/community/licensing.shtml
*/

/*
	This is a compiled version of Dojo, built for deployment and not for
	development. To get an editable version, please visit:

		http://dojotoolkit.org

	for documentation and information on getting the source.
*/

if(typeof dojo=="undefined"){
var dj_global=this;
function dj_undef(_1,_2){
if(_2==null){
_2=dj_global;
}
return (typeof _2[_1]=="undefined");
}
if(dj_undef("djConfig")){
var djConfig={};
}
if(dj_undef("dojo")){
var dojo={};
}
dojo.version={major:0,minor:3,patch:1,flag:"",revision:Number("$Rev: 4342 $".match(/[0-9]+/)[0]),toString:function(){
with(dojo.version){
return major+"."+minor+"."+patch+flag+" ("+revision+")";
}
}};
dojo.evalProp=function(_3,_4,_5){
return (_4&&!dj_undef(_3,_4)?_4[_3]:(_5?(_4[_3]={}):undefined));
};
dojo.parseObjPath=function(_6,_7,_8){
var _9=(_7!=null?_7:dj_global);
var _a=_6.split(".");
var _b=_a.pop();
for(var i=0,l=_a.length;i<l&&_9;i++){
_9=dojo.evalProp(_a[i],_9,_8);
}
return {obj:_9,prop:_b};
};
dojo.evalObjPath=function(_d,_e){
if(typeof _d!="string"){
return dj_global;
}
if(_d.indexOf(".")==-1){
return dojo.evalProp(_d,dj_global,_e);
}
var _f=dojo.parseObjPath(_d,dj_global,_e);
if(_f){
return dojo.evalProp(_f.prop,_f.obj,_e);
}
return null;
};
dojo.errorToString=function(_10){
if(!dj_undef("message",_10)){
return _10.message;
}else{
if(!dj_undef("description",_10)){
return _10.description;
}else{
return _10;
}
}
};
dojo.raise=function(_11,_12){
if(_12){
_11=_11+": "+dojo.errorToString(_12);
}
try{
dojo.hostenv.println("FATAL: "+_11);
}
catch(e){
}
throw Error(_11);
};
dojo.debug=function(){
};
dojo.debugShallow=function(obj){
};
dojo.profile={start:function(){
},end:function(){
},stop:function(){
},dump:function(){
}};
function dj_eval(_14){
return dj_global.eval?dj_global.eval(_14):eval(_14);
}
dojo.unimplemented=function(_15,_16){
var _17="'"+_15+"' not implemented";
if(_16!=null){
_17+=" "+_16;
}
dojo.raise(_17);
};
dojo.deprecated=function(_18,_19,_1a){
var _1b="DEPRECATED: "+_18;
if(_19){
_1b+=" "+_19;
}
if(_1a){
_1b+=" -- will be removed in version: "+_1a;
}
dojo.debug(_1b);
};
dojo.inherits=function(_1c,_1d){
if(typeof _1d!="function"){
dojo.raise("dojo.inherits: superclass argument ["+_1d+"] must be a function (subclass: ["+_1c+"']");
}
_1c.prototype=new _1d();
_1c.prototype.constructor=_1c;
_1c.superclass=_1d.prototype;
_1c["super"]=_1d.prototype;
};
dojo.render=(function(){
function vscaffold(_1e,_1f){
var tmp={capable:false,support:{builtin:false,plugin:false},prefixes:_1e};
for(var _21 in _1f){
tmp[_21]=false;
}
return tmp;
}
return {name:"",ver:dojo.version,os:{win:false,linux:false,osx:false},html:vscaffold(["html"],["ie","opera","khtml","safari","moz"]),svg:vscaffold(["svg"],["corel","adobe","batik"]),vml:vscaffold(["vml"],["ie"]),swf:vscaffold(["Swf","Flash","Mm"],["mm"]),swt:vscaffold(["Swt"],["ibm"])};
})();
dojo.hostenv=(function(){
var _22={isDebug:false,allowQueryConfig:false,baseScriptUri:"",baseRelativePath:"",libraryScriptUri:"",iePreventClobber:false,ieClobberMinimal:true,preventBackButtonFix:true,searchIds:[],parseWidgets:true};
if(typeof djConfig=="undefined"){
djConfig=_22;
}else{
for(var _23 in _22){
if(typeof djConfig[_23]=="undefined"){
djConfig[_23]=_22[_23];
}
}
}
return {name_:"(unset)",version_:"(unset)",getName:function(){
return this.name_;
},getVersion:function(){
return this.version_;
},getText:function(uri){
dojo.unimplemented("getText","uri="+uri);
}};
})();
dojo.hostenv.getBaseScriptUri=function(){
if(djConfig.baseScriptUri.length){
return djConfig.baseScriptUri;
}
var uri=new String(djConfig.libraryScriptUri||djConfig.baseRelativePath);
if(!uri){
dojo.raise("Nothing returned by getLibraryScriptUri(): "+uri);
}
var _26=uri.lastIndexOf("/");
djConfig.baseScriptUri=djConfig.baseRelativePath;
return djConfig.baseScriptUri;
};
(function(){
var _27={pkgFileName:"__package__",loading_modules_:{},loaded_modules_:{},addedToLoadingCount:[],removedFromLoadingCount:[],inFlightCount:0,modulePrefixes_:{dojo:{name:"dojo",value:"src"}},setModulePrefix:function(_28,_29){
this.modulePrefixes_[_28]={name:_28,value:_29};
},getModulePrefix:function(_2a){
var mp=this.modulePrefixes_;
if((mp[_2a])&&(mp[_2a]["name"])){
return mp[_2a].value;
}
return _2a;
},getTextStack:[],loadUriStack:[],loadedUris:[],post_load_:false,modulesLoadedListeners:[],unloadListeners:[],loadNotifying:false};
for(var _2c in _27){
dojo.hostenv[_2c]=_27[_2c];
}
})();
dojo.hostenv.loadPath=function(_2d,_2e,cb){
var uri;
if((_2d.charAt(0)=="/")||(_2d.match(/^\w+:/))){
uri=_2d;
}else{
uri=this.getBaseScriptUri()+_2d;
}
if(djConfig.cacheBust&&dojo.render.html.capable){
uri+="?"+String(djConfig.cacheBust).replace(/\W+/g,"");
}
try{
return ((!_2e)?this.loadUri(uri,cb):this.loadUriAndCheck(uri,_2e,cb));
}
catch(e){
dojo.debug(e);
return false;
}
};
dojo.hostenv.loadUri=function(uri,cb){
if(this.loadedUris[uri]){
return 1;
}
var _33=this.getText(uri,null,true);
if(_33==null){
return 0;
}
this.loadedUris[uri]=true;
if(cb){
_33="("+_33+")";
}
var _34=dj_eval(_33);
if(cb){
cb(_34);
}
return 1;
};
dojo.hostenv.loadUriAndCheck=function(uri,_36,cb){
var ok=true;
try{
ok=this.loadUri(uri,cb);
}
catch(e){
dojo.debug("failed loading ",uri," with error: ",e);
}
return ((ok)&&(this.findModule(_36,false)))?true:false;
};
dojo.loaded=function(){
};
dojo.unloaded=function(){
};
dojo.hostenv.loaded=function(){
this.loadNotifying=true;
this.post_load_=true;
var mll=this.modulesLoadedListeners;
for(var x=0;x<mll.length;x++){
mll[x]();
}
this.modulesLoadedListeners=[];
this.loadNotifying=false;
dojo.loaded();
};
dojo.hostenv.unloaded=function(){
var mll=this.unloadListeners;
while(mll.length){
(mll.pop())();
}
dojo.unloaded();
};
dojo.addOnLoad=function(obj,_3d){
var dh=dojo.hostenv;
if(arguments.length==1){
dh.modulesLoadedListeners.push(obj);
}else{
if(arguments.length>1){
dh.modulesLoadedListeners.push(function(){
obj[_3d]();
});
}
}
if(dh.post_load_&&dh.inFlightCount==0&&!dh.loadNotifying){
dh.callLoaded();
}
};
dojo.addOnUnload=function(obj,_40){
var dh=dojo.hostenv;
if(arguments.length==1){
dh.unloadListeners.push(obj);
}else{
if(arguments.length>1){
dh.unloadListeners.push(function(){
obj[_40]();
});
}
}
};
dojo.hostenv.modulesLoaded=function(){
if(this.post_load_){
return;
}
if((this.loadUriStack.length==0)&&(this.getTextStack.length==0)){
if(this.inFlightCount>0){
dojo.debug("files still in flight!");
return;
}
dojo.hostenv.callLoaded();
}
};
dojo.hostenv.callLoaded=function(){
if(typeof setTimeout=="object"){
setTimeout("dojo.hostenv.loaded();",0);
}else{
dojo.hostenv.loaded();
}
};
dojo.hostenv.getModuleSymbols=function(_42){
var _43=_42.split(".");
for(var i=_43.length-1;i>0;i--){
var _45=_43.slice(0,i).join(".");
var _46=this.getModulePrefix(_45);
if(_46!=_45){
_43.splice(0,i,_46);
break;
}
}
return _43;
};
dojo.hostenv._global_omit_module_check=false;
dojo.hostenv.loadModule=function(_47,_48,_49){
if(!_47){
return;
}
_49=this._global_omit_module_check||_49;
var _4a=this.findModule(_47,false);
if(_4a){
return _4a;
}
if(dj_undef(_47,this.loading_modules_)){
this.addedToLoadingCount.push(_47);
}
this.loading_modules_[_47]=1;
var _4b=_47.replace(/\./g,"/")+".js";
var _4c=this.getModuleSymbols(_47);
var _4d=((_4c[0].charAt(0)!="/")&&(!_4c[0].match(/^\w+:/)));
var _4e=_4c[_4c.length-1];
var _4f=_47.split(".");
if(_4e=="*"){
_47=(_4f.slice(0,-1)).join(".");
while(_4c.length){
_4c.pop();
_4c.push(this.pkgFileName);
_4b=_4c.join("/")+".js";
if(_4d&&(_4b.charAt(0)=="/")){
_4b=_4b.slice(1);
}
ok=this.loadPath(_4b,((!_49)?_47:null));
if(ok){
break;
}
_4c.pop();
}
}else{
_4b=_4c.join("/")+".js";
_47=_4f.join(".");
var ok=this.loadPath(_4b,((!_49)?_47:null));
if((!ok)&&(!_48)){
_4c.pop();
while(_4c.length){
_4b=_4c.join("/")+".js";
ok=this.loadPath(_4b,((!_49)?_47:null));
if(ok){
break;
}
_4c.pop();
_4b=_4c.join("/")+"/"+this.pkgFileName+".js";
if(_4d&&(_4b.charAt(0)=="/")){
_4b=_4b.slice(1);
}
ok=this.loadPath(_4b,((!_49)?_47:null));
if(ok){
break;
}
}
}
if((!ok)&&(!_49)){
dojo.raise("Could not load '"+_47+"'; last tried '"+_4b+"'");
}
}
if(!_49&&!this["isXDomain"]){
_4a=this.findModule(_47,false);
if(!_4a){
dojo.raise("symbol '"+_47+"' is not defined after loading '"+_4b+"'");
}
}
return _4a;
};
dojo.hostenv.startPackage=function(_51){
var _52=dojo.evalObjPath((_51.split(".").slice(0,-1)).join("."));
this.loaded_modules_[(new String(_51)).toLowerCase()]=_52;
var _53=_51.split(/\./);
if(_53[_53.length-1]=="*"){
_53.pop();
}
return dojo.evalObjPath(_53.join("."),true);
};
dojo.hostenv.findModule=function(_54,_55){
var lmn=(new String(_54)).toLowerCase();
if(this.loaded_modules_[lmn]){
return this.loaded_modules_[lmn];
}
var _57=dojo.evalObjPath(_54);
if((_54)&&(typeof _57!="undefined")&&(_57)){
this.loaded_modules_[lmn]=_57;
return _57;
}
if(_55){
dojo.raise("no loaded module named '"+_54+"'");
}
return null;
};
dojo.kwCompoundRequire=function(_58){
var _59=_58["common"]||[];
var _5a=(_58[dojo.hostenv.name_])?_59.concat(_58[dojo.hostenv.name_]||[]):_59.concat(_58["default"]||[]);
for(var x=0;x<_5a.length;x++){
var _5c=_5a[x];
if(_5c.constructor==Array){
dojo.hostenv.loadModule.apply(dojo.hostenv,_5c);
}else{
dojo.hostenv.loadModule(_5c);
}
}
};
dojo.require=function(){
dojo.hostenv.loadModule.apply(dojo.hostenv,arguments);
};
dojo.requireIf=function(){
if((arguments[0]===true)||(arguments[0]=="common")||(arguments[0]&&dojo.render[arguments[0]].capable)){
var _5d=[];
for(var i=1;i<arguments.length;i++){
_5d.push(arguments[i]);
}
dojo.require.apply(dojo,_5d);
}
};
dojo.requireAfterIf=dojo.requireIf;
dojo.provide=function(){
return dojo.hostenv.startPackage.apply(dojo.hostenv,arguments);
};
dojo.setModulePrefix=function(_5f,_60){
return dojo.hostenv.setModulePrefix(_5f,_60);
};
dojo.exists=function(obj,_62){
var p=_62.split(".");
for(var i=0;i<p.length;i++){
if(!(obj[p[i]])){
return false;
}
obj=obj[p[i]];
}
return true;
};
}
if(typeof window=="undefined"){
dojo.raise("no window object");
}
(function(){
if(djConfig.allowQueryConfig){
var _65=document.location.toString();
var _66=_65.split("?",2);
if(_66.length>1){
var _67=_66[1];
var _68=_67.split("&");
for(var x in _68){
var sp=_68[x].split("=");
if((sp[0].length>9)&&(sp[0].substr(0,9)=="djConfig.")){
var opt=sp[0].substr(9);
try{
djConfig[opt]=eval(sp[1]);
}
catch(e){
djConfig[opt]=sp[1];
}
}
}
}
}
if(((djConfig["baseScriptUri"]=="")||(djConfig["baseRelativePath"]==""))&&(document&&document.getElementsByTagName)){
var _6c=document.getElementsByTagName("script");
var _6d=/(__package__|dojo|bootstrap1)\.js([\?\.]|$)/i;
for(var i=0;i<_6c.length;i++){
var src=_6c[i].getAttribute("src");
if(!src){
continue;
}
var m=src.match(_6d);
if(m){
var _71=src.substring(0,m.index);
if(src.indexOf("bootstrap1")>-1){
_71+="../";
}
if(!this["djConfig"]){
djConfig={};
}
if(djConfig["baseScriptUri"]==""){
djConfig["baseScriptUri"]=_71;
}
if(djConfig["baseRelativePath"]==""){
djConfig["baseRelativePath"]=_71;
}
break;
}
}
}
var dr=dojo.render;
var drh=dojo.render.html;
var drs=dojo.render.svg;
var dua=drh.UA=navigator.userAgent;
var dav=drh.AV=navigator.appVersion;
var t=true;
var f=false;
drh.capable=t;
drh.support.builtin=t;
dr.ver=parseFloat(drh.AV);
dr.os.mac=dav.indexOf("Macintosh")>=0;
dr.os.win=dav.indexOf("Windows")>=0;
dr.os.linux=dav.indexOf("X11")>=0;
drh.opera=dua.indexOf("Opera")>=0;
drh.khtml=(dav.indexOf("Konqueror")>=0)||(dav.indexOf("Safari")>=0);
drh.safari=dav.indexOf("Safari")>=0;
var _79=dua.indexOf("Gecko");
drh.mozilla=drh.moz=(_79>=0)&&(!drh.khtml);
if(drh.mozilla){
drh.geckoVersion=dua.substring(_79+6,_79+14);
}
drh.ie=(document.all)&&(!drh.opera);
drh.ie50=drh.ie&&dav.indexOf("MSIE 5.0")>=0;
drh.ie55=drh.ie&&dav.indexOf("MSIE 5.5")>=0;
drh.ie60=drh.ie&&dav.indexOf("MSIE 6.0")>=0;
drh.ie70=drh.ie&&dav.indexOf("MSIE 7.0")>=0;
dojo.locale=(drh.ie?navigator.userLanguage:navigator.language).toLowerCase();
dr.vml.capable=drh.ie;
drs.capable=f;
drs.support.plugin=f;
drs.support.builtin=f;
if(document.implementation&&document.implementation.hasFeature&&document.implementation.hasFeature("org.w3c.dom.svg","1.0")){
drs.capable=t;
drs.support.builtin=t;
drs.support.plugin=f;
}
})();
dojo.hostenv.startPackage("dojo.hostenv");
dojo.render.name=dojo.hostenv.name_="browser";
dojo.hostenv.searchIds=[];
dojo.hostenv._XMLHTTP_PROGIDS=["Msxml2.XMLHTTP","Microsoft.XMLHTTP","Msxml2.XMLHTTP.4.0"];
dojo.hostenv.getXmlhttpObject=function(){
var _7a=null;
var _7b=null;
try{
_7a=new XMLHttpRequest();
}
catch(e){
}
if(!_7a){
for(var i=0;i<3;++i){
var _7d=dojo.hostenv._XMLHTTP_PROGIDS[i];
try{
_7a=new ActiveXObject(_7d);
}
catch(e){
_7b=e;
}
if(_7a){
dojo.hostenv._XMLHTTP_PROGIDS=[_7d];
break;
}
}
}
if(!_7a){
return dojo.raise("XMLHTTP not available",_7b);
}
return _7a;
};
dojo.hostenv.getText=function(uri,_7f,_80){
var _81=this.getXmlhttpObject();
if(_7f){
_81.onreadystatechange=function(){
if(4==_81.readyState){
if((!_81["status"])||((200<=_81.status)&&(300>_81.status))){
_7f(_81.responseText);
}
}
};
}
_81.open("GET",uri,_7f?true:false);
try{
_81.send(null);
if(_7f){
return null;
}
if((_81["status"])&&((200>_81.status)||(300<=_81.status))){
throw Error("Unable to load "+uri+" status:"+_81.status);
}
}
catch(e){
if((_80)&&(!_7f)){
return null;
}else{
throw e;
}
}
return _81.responseText;
};
dojo.hostenv.defaultDebugContainerId="dojoDebug";
dojo.hostenv._println_buffer=[];
dojo.hostenv._println_safe=false;
dojo.hostenv.println=function(_82){
if(!dojo.hostenv._println_safe){
dojo.hostenv._println_buffer.push(_82);
}else{
try{
var _83=document.getElementById(djConfig.debugContainerId?djConfig.debugContainerId:dojo.hostenv.defaultDebugContainerId);
if(!_83){
_83=document.getElementsByTagName("body")[0]||document.body;
}
var div=document.createElement("div");
div.appendChild(document.createTextNode(_82));
_83.appendChild(div);
}
catch(e){
try{
document.write("<div>"+_82+"</div>");
}
catch(e2){
window.status=_82;
}
}
}
};
dojo.addOnLoad(function(){
dojo.hostenv._println_safe=true;
while(dojo.hostenv._println_buffer.length>0){
dojo.hostenv.println(dojo.hostenv._println_buffer.shift());
}
});
function dj_addNodeEvtHdlr(_85,_86,fp,_88){
var _89=_85["on"+_86]||function(){
};
_85["on"+_86]=function(){
fp.apply(_85,arguments);
_89.apply(_85,arguments);
};
return true;
}
dj_addNodeEvtHdlr(window,"load",function(){
if(arguments.callee.initialized){
return;
}
arguments.callee.initialized=true;
var _8a=function(){
if(dojo.render.html.ie){
dojo.hostenv.makeWidgets();
}
};
if(dojo.hostenv.inFlightCount==0){
_8a();
dojo.hostenv.modulesLoaded();
}else{
dojo.addOnLoad(_8a);
}
});
dj_addNodeEvtHdlr(window,"unload",function(){
dojo.hostenv.unloaded();
});
dojo.hostenv.makeWidgets=function(){
var _8b=[];
if(djConfig.searchIds&&djConfig.searchIds.length>0){
_8b=_8b.concat(djConfig.searchIds);
}
if(dojo.hostenv.searchIds&&dojo.hostenv.searchIds.length>0){
_8b=_8b.concat(dojo.hostenv.searchIds);
}
if((djConfig.parseWidgets)||(_8b.length>0)){
if(dojo.evalObjPath("dojo.widget.Parse")){
var _8c=new dojo.xml.Parse();
if(_8b.length>0){
for(var x=0;x<_8b.length;x++){
var _8e=document.getElementById(_8b[x]);
if(!_8e){
continue;
}
var _8f=_8c.parseElement(_8e,null,true);
dojo.widget.getParser().createComponents(_8f);
}
}else{
if(djConfig.parseWidgets){
var _8f=_8c.parseElement(document.getElementsByTagName("body")[0]||document.body,null,true);
dojo.widget.getParser().createComponents(_8f);
}
}
}
}
};
dojo.addOnLoad(function(){
if(!dojo.render.html.ie){
dojo.hostenv.makeWidgets();
}
});
try{
if(dojo.render.html.ie){
document.write("<style>v:*{ behavior:url(#default#VML); }</style>");
document.write("<xml:namespace ns=\"urn:schemas-microsoft-com:vml\" prefix=\"v\"/>");
}
}
catch(e){
}
dojo.hostenv.writeIncludes=function(){
};
dojo.byId=function(id,doc){
if(id&&(typeof id=="string"||id instanceof String)){
if(!doc){
doc=document;
}
return doc.getElementById(id);
}
return id;
};
(function(){
if(typeof dj_usingBootstrap!="undefined"){
return;
}
var _92=false;
var _93=false;
var _94=false;
if((typeof this["load"]=="function")&&((typeof this["Packages"]=="function")||(typeof this["Packages"]=="object"))){
_92=true;
}else{
if(typeof this["load"]=="function"){
_93=true;
}else{
if(window.widget){
_94=true;
}
}
}
var _95=[];
if((this["djConfig"])&&((djConfig["isDebug"])||(djConfig["debugAtAllCosts"]))){
_95.push("debug.js");
}
if((this["djConfig"])&&(djConfig["debugAtAllCosts"])&&(!_92)&&(!_94)){
_95.push("browser_debug.js");
}
if((this["djConfig"])&&(djConfig["compat"])){
_95.push("compat/"+djConfig["compat"]+".js");
}
var _96=djConfig["baseScriptUri"];
if((this["djConfig"])&&(djConfig["baseLoaderUri"])){
_96=djConfig["baseLoaderUri"];
}
for(var x=0;x<_95.length;x++){
var _98=_96+"src/"+_95[x];
if(_92||_93){
load(_98);
}else{
try{
document.write("<scr"+"ipt type='text/javascript' src='"+_98+"'></scr"+"ipt>");
}
catch(e){
var _99=document.createElement("script");
_99.src=_98;
document.getElementsByTagName("head")[0].appendChild(_99);
}
}
}
})();
dojo.fallback_locale="en";
dojo.normalizeLocale=function(_9a){
return _9a?_9a.toLowerCase():dojo.locale;
};
dojo.requireLocalization=function(_9b,_9c,_9d){
dojo.debug("EXPERIMENTAL: dojo.requireLocalization");
var _9e=dojo.hostenv.getModuleSymbols(_9b);
var _9f=_9e.concat("nls").join("/");
_9d=dojo.normalizeLocale(_9d);
var _a0=_9d.split("-");
var _a1=[];
for(var i=_a0.length;i>0;i--){
_a1.push(_a0.slice(0,i).join("-"));
}
if(_a1[_a1.length-1]!=dojo.fallback_locale){
_a1.push(dojo.fallback_locale);
}
var _a3=[_9b,"_nls",_9c].join(".");
var _a4=dojo.hostenv.startPackage(_a3);
dojo.hostenv.loaded_modules_[_a3]=_a4;
var _a5=false;
for(var i=_a1.length-1;i>=0;i--){
var loc=_a1[i];
var pkg=[_a3,loc].join(".");
var _a8=false;
if(!dojo.hostenv.findModule(pkg)){
dojo.hostenv.loaded_modules_[pkg]=null;
var _a9=[_9f,loc,_9c].join("/")+".js";
_a8=dojo.hostenv.loadPath(_a9,null,function(_aa){
_a4[loc]=_aa;
if(_a5){
for(var x in _a5){
if(!_a4[loc][x]){
_a4[loc][x]=_a5[x];
}
}
}
});
}else{
_a8=true;
}
if(_a8&&_a4[loc]){
_a5=_a4[loc];
}
}
};
dojo.provide("dojo.string.common");
dojo.require("dojo.string");
dojo.string.trim=function(str,wh){
if(!str.replace){
return str;
}
if(!str.length){
return str;
}
var re=(wh>0)?(/^\s+/):(wh<0)?(/\s+$/):(/^\s+|\s+$/g);
return str.replace(re,"");
};
dojo.string.trimStart=function(str){
return dojo.string.trim(str,1);
};
dojo.string.trimEnd=function(str){
return dojo.string.trim(str,-1);
};
dojo.string.repeat=function(str,_b2,_b3){
var out="";
for(var i=0;i<_b2;i++){
out+=str;
if(_b3&&i<_b2-1){
out+=_b3;
}
}
return out;
};
dojo.string.pad=function(str,len,c,dir){
var out=String(str);
if(!c){
c="0";
}
if(!dir){
dir=1;
}
while(out.length<len){
if(dir>0){
out=c+out;
}else{
out+=c;
}
}
return out;
};
dojo.string.padLeft=function(str,len,c){
return dojo.string.pad(str,len,c,1);
};
dojo.string.padRight=function(str,len,c){
return dojo.string.pad(str,len,c,-1);
};
dojo.provide("dojo.string");
dojo.require("dojo.string.common");
dojo.provide("dojo.lang.common");
dojo.require("dojo.lang");
dojo.lang._mixin=function(obj,_c2){
var _c3={};
for(var x in _c2){
if(typeof _c3[x]=="undefined"||_c3[x]!=_c2[x]){
obj[x]=_c2[x];
}
}
if(dojo.render.html.ie&&dojo.lang.isFunction(_c2["toString"])&&_c2["toString"]!=obj["toString"]){
obj.toString=_c2.toString;
}
return obj;
};
dojo.lang.mixin=function(obj,_c6){
for(var i=1,l=arguments.length;i<l;i++){
dojo.lang._mixin(obj,arguments[i]);
}
return obj;
};
dojo.lang.extend=function(_c8,_c9){
for(var i=1,l=arguments.length;i<l;i++){
dojo.lang._mixin(_c8.prototype,arguments[i]);
}
return _c8;
};
dojo.lang.find=function(arr,val,_cd,_ce){
if(!dojo.lang.isArrayLike(arr)&&dojo.lang.isArrayLike(val)){
var a=arr;
arr=val;
val=a;
}
var _d0=dojo.lang.isString(arr);
if(_d0){
arr=arr.split("");
}
if(_ce){
var _d1=-1;
var i=arr.length-1;
var end=-1;
}else{
var _d1=1;
var i=0;
var end=arr.length;
}
if(_cd){
while(i!=end){
if(arr[i]===val){
return i;
}
i+=_d1;
}
}else{
while(i!=end){
if(arr[i]==val){
return i;
}
i+=_d1;
}
}
return -1;
};
dojo.lang.indexOf=dojo.lang.find;
dojo.lang.findLast=function(arr,val,_d6){
return dojo.lang.find(arr,val,_d6,true);
};
dojo.lang.lastIndexOf=dojo.lang.findLast;
dojo.lang.inArray=function(arr,val){
return dojo.lang.find(arr,val)>-1;
};
dojo.lang.isObject=function(wh){
if(typeof wh=="undefined"){
return false;
}
return (typeof wh=="object"||wh===null||dojo.lang.isArray(wh)||dojo.lang.isFunction(wh));
};
dojo.lang.isArray=function(wh){
return (wh instanceof Array||typeof wh=="array");
};
dojo.lang.isArrayLike=function(wh){
if(dojo.lang.isString(wh)){
return false;
}
if(dojo.lang.isFunction(wh)){
return false;
}
if(dojo.lang.isArray(wh)){
return true;
}
if(typeof wh!="undefined"&&wh&&dojo.lang.isNumber(wh.length)&&isFinite(wh.length)){
return true;
}
return false;
};
dojo.lang.isFunction=function(wh){
if(!wh){
return false;
}
return (wh instanceof Function||typeof wh=="function");
};
dojo.lang.isString=function(wh){
return (wh instanceof String||typeof wh=="string");
};
dojo.lang.isAlien=function(wh){
if(!wh){
return false;
}
return !dojo.lang.isFunction()&&/\{\s*\[native code\]\s*\}/.test(String(wh));
};
dojo.lang.isBoolean=function(wh){
return (wh instanceof Boolean||typeof wh=="boolean");
};
dojo.lang.isNumber=function(wh){
return (wh instanceof Number||typeof wh=="number");
};
dojo.lang.isUndefined=function(wh){
return ((wh==undefined)&&(typeof wh=="undefined"));
};
dojo.provide("dojo.lang.extras");
dojo.require("dojo.lang.common");
dojo.lang.setTimeout=function(_e2,_e3){
var _e4=window,argsStart=2;
if(!dojo.lang.isFunction(_e2)){
_e4=_e2;
_e2=_e3;
_e3=arguments[2];
argsStart++;
}
if(dojo.lang.isString(_e2)){
_e2=_e4[_e2];
}
var _e5=[];
for(var i=argsStart;i<arguments.length;i++){
_e5.push(arguments[i]);
}
return setTimeout(function(){
_e2.apply(_e4,_e5);
},_e3);
};
dojo.lang.getNameInObj=function(ns,_e8){
if(!ns){
ns=dj_global;
}
for(var x in ns){
if(ns[x]===_e8){
return new String(x);
}
}
return null;
};
dojo.lang.shallowCopy=function(obj){
var ret={},key;
for(key in obj){
if(dojo.lang.isUndefined(ret[key])){
ret[key]=obj[key];
}
}
return ret;
};
dojo.lang.firstValued=function(){
for(var i=0;i<arguments.length;i++){
if(typeof arguments[i]!="undefined"){
return arguments[i];
}
}
return undefined;
};
dojo.lang.getObjPathValue=function(_ed,_ee,_ef){
with(dojo.parseObjPath(_ed,_ee,_ef)){
return dojo.evalProp(prop,obj,_ef);
}
};
dojo.lang.setObjPathValue=function(_f0,_f1,_f2,_f3){
if(arguments.length<4){
_f3=true;
}
with(dojo.parseObjPath(_f0,_f2,_f3)){
if(obj&&(_f3||(prop in obj))){
obj[prop]=_f1;
}
}
};
dojo.provide("dojo.io.IO");
dojo.require("dojo.string");
dojo.require("dojo.lang.extras");
dojo.io.transports=[];
dojo.io.hdlrFuncNames=["load","error","timeout"];
dojo.io.Request=function(url,_f5,_f6,_f7){
if((arguments.length==1)&&(arguments[0].constructor==Object)){
this.fromKwArgs(arguments[0]);
}else{
this.url=url;
if(_f5){
this.mimetype=_f5;
}
if(_f6){
this.transport=_f6;
}
if(arguments.length>=4){
this.changeUrl=_f7;
}
}
};
dojo.lang.extend(dojo.io.Request,{url:"",mimetype:"text/plain",method:"GET",content:undefined,transport:undefined,changeUrl:undefined,formNode:undefined,sync:false,bindSuccess:false,useCache:false,preventCache:false,load:function(_f8,_f9,evt){
},error:function(_fb,_fc){
},timeout:function(_fd){
},handle:function(){
},timeoutSeconds:0,abort:function(){
},fromKwArgs:function(_fe){
if(_fe["url"]){
_fe.url=_fe.url.toString();
}
if(_fe["formNode"]){
_fe.formNode=dojo.byId(_fe.formNode);
}
if(!_fe["method"]&&_fe["formNode"]&&_fe["formNode"].method){
_fe.method=_fe["formNode"].method;
}
if(!_fe["handle"]&&_fe["handler"]){
_fe.handle=_fe.handler;
}
if(!_fe["load"]&&_fe["loaded"]){
_fe.load=_fe.loaded;
}
if(!_fe["changeUrl"]&&_fe["changeURL"]){
_fe.changeUrl=_fe.changeURL;
}
_fe.encoding=dojo.lang.firstValued(_fe["encoding"],djConfig["bindEncoding"],"");
_fe.sendTransport=dojo.lang.firstValued(_fe["sendTransport"],djConfig["ioSendTransport"],false);
var _ff=dojo.lang.isFunction;
for(var x=0;x<dojo.io.hdlrFuncNames.length;x++){
var fn=dojo.io.hdlrFuncNames[x];
if(_ff(_fe[fn])){
continue;
}
if(_ff(_fe["handle"])){
_fe[fn]=_fe.handle;
}
}
dojo.lang.mixin(this,_fe);
}});
dojo.io.Error=function(msg,type,num){
this.message=msg;
this.type=type||"unknown";
this.number=num||0;
};
dojo.io.transports.addTransport=function(name){
this.push(name);
this[name]=dojo.io[name];
};
dojo.io.bind=function(_106){
if(!(_106 instanceof dojo.io.Request)){
try{
_106=new dojo.io.Request(_106);
}
catch(e){
dojo.debug(e);
}
}
var _107="";
if(_106["transport"]){
_107=_106["transport"];
if(!this[_107]){
return _106;
}
}else{
for(var x=0;x<dojo.io.transports.length;x++){
var tmp=dojo.io.transports[x];
if((this[tmp])&&(this[tmp].canHandle(_106))){
_107=tmp;
}
}
if(_107==""){
return _106;
}
}
this[_107].bind(_106);
_106.bindSuccess=true;
return _106;
};
dojo.io.queueBind=function(_10a){
if(!(_10a instanceof dojo.io.Request)){
try{
_10a=new dojo.io.Request(_10a);
}
catch(e){
dojo.debug(e);
}
}
var _10b=_10a.load;
_10a.load=function(){
dojo.io._queueBindInFlight=false;
var ret=_10b.apply(this,arguments);
dojo.io._dispatchNextQueueBind();
return ret;
};
var _10d=_10a.error;
_10a.error=function(){
dojo.io._queueBindInFlight=false;
var ret=_10d.apply(this,arguments);
dojo.io._dispatchNextQueueBind();
return ret;
};
dojo.io._bindQueue.push(_10a);
dojo.io._dispatchNextQueueBind();
return _10a;
};
dojo.io._dispatchNextQueueBind=function(){
if(!dojo.io._queueBindInFlight){
dojo.io._queueBindInFlight=true;
if(dojo.io._bindQueue.length>0){
dojo.io.bind(dojo.io._bindQueue.shift());
}else{
dojo.io._queueBindInFlight=false;
}
}
};
dojo.io._bindQueue=[];
dojo.io._queueBindInFlight=false;
dojo.io.argsFromMap=function(map,_110,last){
var enc=/utf/i.test(_110||"")?encodeURIComponent:dojo.string.encodeAscii;
var _113=[];
var _114=new Object();
for(var name in map){
var _116=function(elt){
var val=enc(name)+"="+enc(elt);
_113[(last==name)?"push":"unshift"](val);
};
if(!_114[name]){
var _119=map[name];
if(dojo.lang.isArray(_119)){
dojo.lang.forEach(_119,_116);
}else{
_116(_119);
}
}
}
return _113.join("&");
};
dojo.io.setIFrameSrc=function(_11a,src,_11c){
try{
var r=dojo.render.html;
if(!_11c){
if(r.safari){
_11a.location=src;
}else{
frames[_11a.name].location=src;
}
}else{
var idoc;
if(r.ie){
idoc=_11a.contentWindow.document;
}else{
if(r.safari){
idoc=_11a.document;
}else{
idoc=_11a.contentWindow;
}
}
if(!idoc){
_11a.location=src;
return;
}else{
idoc.location.replace(src);
}
}
}
catch(e){
dojo.debug(e);
dojo.debug("setIFrameSrc: "+e);
}
};
dojo.provide("dojo.lang.array");
dojo.require("dojo.lang.common");
dojo.lang.has=function(obj,name){
try{
return (typeof obj[name]!="undefined");
}
catch(e){
return false;
}
};
dojo.lang.isEmpty=function(obj){
if(dojo.lang.isObject(obj)){
var tmp={};
var _123=0;
for(var x in obj){
if(obj[x]&&(!tmp[x])){
_123++;
break;
}
}
return (_123==0);
}else{
if(dojo.lang.isArrayLike(obj)||dojo.lang.isString(obj)){
return obj.length==0;
}
}
};
dojo.lang.map=function(arr,obj,_127){
var _128=dojo.lang.isString(arr);
if(_128){
arr=arr.split("");
}
if(dojo.lang.isFunction(obj)&&(!_127)){
_127=obj;
obj=dj_global;
}else{
if(dojo.lang.isFunction(obj)&&_127){
var _129=obj;
obj=_127;
_127=_129;
}
}
if(Array.map){
var _12a=Array.map(arr,_127,obj);
}else{
var _12a=[];
for(var i=0;i<arr.length;++i){
_12a.push(_127.call(obj,arr[i]));
}
}
if(_128){
return _12a.join("");
}else{
return _12a;
}
};
dojo.lang.forEach=function(_12c,_12d,_12e){
if(dojo.lang.isString(_12c)){
_12c=_12c.split("");
}
if(Array.forEach){
Array.forEach(_12c,_12d,_12e);
}else{
if(!_12e){
_12e=dj_global;
}
for(var i=0,l=_12c.length;i<l;i++){
_12d.call(_12e,_12c[i],i,_12c);
}
}
};
dojo.lang._everyOrSome=function(_130,arr,_132,_133){
if(dojo.lang.isString(arr)){
arr=arr.split("");
}
if(Array.every){
return Array[(_130)?"every":"some"](arr,_132,_133);
}else{
if(!_133){
_133=dj_global;
}
for(var i=0,l=arr.length;i<l;i++){
var _135=_132.call(_133,arr[i],i,arr);
if((_130)&&(!_135)){
return false;
}else{
if((!_130)&&(_135)){
return true;
}
}
}
return (_130)?true:false;
}
};
dojo.lang.every=function(arr,_137,_138){
return this._everyOrSome(true,arr,_137,_138);
};
dojo.lang.some=function(arr,_13a,_13b){
return this._everyOrSome(false,arr,_13a,_13b);
};
dojo.lang.filter=function(arr,_13d,_13e){
var _13f=dojo.lang.isString(arr);
if(_13f){
arr=arr.split("");
}
if(Array.filter){
var _140=Array.filter(arr,_13d,_13e);
}else{
if(!_13e){
if(arguments.length>=3){
dojo.raise("thisObject doesn't exist!");
}
_13e=dj_global;
}
var _140=[];
for(var i=0;i<arr.length;i++){
if(_13d.call(_13e,arr[i],i,arr)){
_140.push(arr[i]);
}
}
}
if(_13f){
return _140.join("");
}else{
return _140;
}
};
dojo.lang.unnest=function(){
var out=[];
for(var i=0;i<arguments.length;i++){
if(dojo.lang.isArrayLike(arguments[i])){
var add=dojo.lang.unnest.apply(this,arguments[i]);
out=out.concat(add);
}else{
out.push(arguments[i]);
}
}
return out;
};
dojo.lang.toArray=function(_145,_146){
var _147=[];
for(var i=_146||0;i<_145.length;i++){
_147.push(_145[i]);
}
return _147;
};
dojo.provide("dojo.lang.func");
dojo.require("dojo.lang.common");
dojo.lang.hitch=function(_149,_14a){
if(dojo.lang.isString(_14a)){
var fcn=_149[_14a];
}else{
var fcn=_14a;
}
return function(){
return fcn.apply(_149,arguments);
};
};
dojo.lang.anonCtr=0;
dojo.lang.anon={};
dojo.lang.nameAnonFunc=function(_14c,_14d,_14e){
var nso=(_14d||dojo.lang.anon);
if((_14e)||((dj_global["djConfig"])&&(djConfig["slowAnonFuncLookups"]==true))){
for(var x in nso){
if(nso[x]===_14c){
return x;
}
}
}
var ret="__"+dojo.lang.anonCtr++;
while(typeof nso[ret]!="undefined"){
ret="__"+dojo.lang.anonCtr++;
}
nso[ret]=_14c;
return ret;
};
dojo.lang.forward=function(_152){
return function(){
return this[_152].apply(this,arguments);
};
};
dojo.lang.curry=function(ns,func){
var _155=[];
ns=ns||dj_global;
if(dojo.lang.isString(func)){
func=ns[func];
}
for(var x=2;x<arguments.length;x++){
_155.push(arguments[x]);
}
var _157=(func["__preJoinArity"]||func.length)-_155.length;
function gather(_158,_159,_15a){
var _15b=_15a;
var _15c=_159.slice(0);
for(var x=0;x<_158.length;x++){
_15c.push(_158[x]);
}
_15a=_15a-_158.length;
if(_15a<=0){
var res=func.apply(ns,_15c);
_15a=_15b;
return res;
}else{
return function(){
return gather(arguments,_15c,_15a);
};
}
}
return gather([],_155,_157);
};
dojo.lang.curryArguments=function(ns,func,args,_162){
var _163=[];
var x=_162||0;
for(x=_162;x<args.length;x++){
_163.push(args[x]);
}
return dojo.lang.curry.apply(dojo.lang,[ns,func].concat(_163));
};
dojo.lang.tryThese=function(){
for(var x=0;x<arguments.length;x++){
try{
if(typeof arguments[x]=="function"){
var ret=(arguments[x]());
if(ret){
return ret;
}
}
}
catch(e){
dojo.debug(e);
}
}
};
dojo.lang.delayThese=function(farr,cb,_169,_16a){
if(!farr.length){
if(typeof _16a=="function"){
_16a();
}
return;
}
if((typeof _169=="undefined")&&(typeof cb=="number")){
_169=cb;
cb=function(){
};
}else{
if(!cb){
cb=function(){
};
if(!_169){
_169=0;
}
}
}
setTimeout(function(){
(farr.shift())();
cb();
dojo.lang.delayThese(farr,cb,_169,_16a);
},_169);
};
dojo.provide("dojo.string.extras");
dojo.require("dojo.string.common");
dojo.require("dojo.lang");
dojo.string.substituteParams=function(_16b,hash){
var map=(typeof hash=="object")?hash:dojo.lang.toArray(arguments,1);
return _16b.replace(/\%\{(\w+)\}/g,function(_16e,key){
return map[key]||dojo.raise("Substitution not found: "+key);
});
};
dojo.string.paramString=function(str,_171,_172){
dojo.deprecated("dojo.string.paramString","use dojo.string.substituteParams instead","0.4");
for(var name in _171){
var re=new RegExp("\\%\\{"+name+"\\}","g");
str=str.replace(re,_171[name]);
}
if(_172){
str=str.replace(/%\{([^\}\s]+)\}/g,"");
}
return str;
};
dojo.string.capitalize=function(str){
if(!dojo.lang.isString(str)){
return "";
}
if(arguments.length==0){
str=this;
}
var _176=str.split(" ");
for(var i=0;i<_176.length;i++){
_176[i]=_176[i].charAt(0).toUpperCase()+_176[i].substring(1);
}
return _176.join(" ");
};
dojo.string.isBlank=function(str){
if(!dojo.lang.isString(str)){
return true;
}
return (dojo.string.trim(str).length==0);
};
dojo.string.encodeAscii=function(str){
if(!dojo.lang.isString(str)){
return str;
}
var ret="";
var _17b=escape(str);
var _17c,re=/%u([0-9A-F]{4})/i;
while((_17c=_17b.match(re))){
var num=Number("0x"+_17c[1]);
var _17e=escape("&#"+num+";");
ret+=_17b.substring(0,_17c.index)+_17e;
_17b=_17b.substring(_17c.index+_17c[0].length);
}
ret+=_17b.replace(/\+/g,"%2B");
return ret;
};
dojo.string.escape=function(type,str){
var args=dojo.lang.toArray(arguments,1);
switch(type.toLowerCase()){
case "xml":
case "html":
case "xhtml":
return dojo.string.escapeXml.apply(this,args);
case "sql":
return dojo.string.escapeSql.apply(this,args);
case "regexp":
case "regex":
return dojo.string.escapeRegExp.apply(this,args);
case "javascript":
case "jscript":
case "js":
return dojo.string.escapeJavaScript.apply(this,args);
case "ascii":
return dojo.string.encodeAscii.apply(this,args);
default:
return str;
}
};
dojo.string.escapeXml=function(str,_183){
str=str.replace(/&/gm,"&amp;").replace(/</gm,"&lt;").replace(/>/gm,"&gt;").replace(/"/gm,"&quot;");
if(!_183){
str=str.replace(/'/gm,"&#39;");
}
return str;
};
dojo.string.escapeSql=function(str){
return str.replace(/'/gm,"''");
};
dojo.string.escapeRegExp=function(str){
return str.replace(/\\/gm,"\\\\").replace(/([\f\b\n\t\r[\^$|?*+(){}])/gm,"\\$1");
};
dojo.string.escapeJavaScript=function(str){
return str.replace(/(["'\f\b\n\t\r])/gm,"\\$1");
};
dojo.string.escapeString=function(str){
return ("\""+str.replace(/(["\\])/g,"\\$1")+"\"").replace(/[\f]/g,"\\f").replace(/[\b]/g,"\\b").replace(/[\n]/g,"\\n").replace(/[\t]/g,"\\t").replace(/[\r]/g,"\\r");
};
dojo.string.summary=function(str,len){
if(!len||str.length<=len){
return str;
}else{
return str.substring(0,len).replace(/\.+$/,"")+"...";
}
};
dojo.string.endsWith=function(str,end,_18c){
if(_18c){
str=str.toLowerCase();
end=end.toLowerCase();
}
if((str.length-end.length)<0){
return false;
}
return str.lastIndexOf(end)==str.length-end.length;
};
dojo.string.endsWithAny=function(str){
for(var i=1;i<arguments.length;i++){
if(dojo.string.endsWith(str,arguments[i])){
return true;
}
}
return false;
};
dojo.string.startsWith=function(str,_190,_191){
if(_191){
str=str.toLowerCase();
_190=_190.toLowerCase();
}
return str.indexOf(_190)==0;
};
dojo.string.startsWithAny=function(str){
for(var i=1;i<arguments.length;i++){
if(dojo.string.startsWith(str,arguments[i])){
return true;
}
}
return false;
};
dojo.string.has=function(str){
for(var i=1;i<arguments.length;i++){
if(str.indexOf(arguments[i])>-1){
return true;
}
}
return false;
};
dojo.string.normalizeNewlines=function(text,_197){
if(_197=="\n"){
text=text.replace(/\r\n/g,"\n");
text=text.replace(/\r/g,"\n");
}else{
if(_197=="\r"){
text=text.replace(/\r\n/g,"\r");
text=text.replace(/\n/g,"\r");
}else{
text=text.replace(/([^\r])\n/g,"$1\r\n");
text=text.replace(/\r([^\n])/g,"\r\n$1");
}
}
return text;
};
dojo.string.splitEscaped=function(str,_199){
var _19a=[];
for(var i=0,prevcomma=0;i<str.length;i++){
if(str.charAt(i)=="\\"){
i++;
continue;
}
if(str.charAt(i)==_199){
_19a.push(str.substring(prevcomma,i));
prevcomma=i+1;
}
}
_19a.push(str.substr(prevcomma));
return _19a;
};
dojo.provide("dojo.dom");
dojo.require("dojo.lang.array");
dojo.dom.ELEMENT_NODE=1;
dojo.dom.ATTRIBUTE_NODE=2;
dojo.dom.TEXT_NODE=3;
dojo.dom.CDATA_SECTION_NODE=4;
dojo.dom.ENTITY_REFERENCE_NODE=5;
dojo.dom.ENTITY_NODE=6;
dojo.dom.PROCESSING_INSTRUCTION_NODE=7;
dojo.dom.COMMENT_NODE=8;
dojo.dom.DOCUMENT_NODE=9;
dojo.dom.DOCUMENT_TYPE_NODE=10;
dojo.dom.DOCUMENT_FRAGMENT_NODE=11;
dojo.dom.NOTATION_NODE=12;
dojo.dom.dojoml="http://www.dojotoolkit.org/2004/dojoml";
dojo.dom.xmlns={svg:"http://www.w3.org/2000/svg",smil:"http://www.w3.org/2001/SMIL20/",mml:"http://www.w3.org/1998/Math/MathML",cml:"http://www.xml-cml.org",xlink:"http://www.w3.org/1999/xlink",xhtml:"http://www.w3.org/1999/xhtml",xul:"http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul",xbl:"http://www.mozilla.org/xbl",fo:"http://www.w3.org/1999/XSL/Format",xsl:"http://www.w3.org/1999/XSL/Transform",xslt:"http://www.w3.org/1999/XSL/Transform",xi:"http://www.w3.org/2001/XInclude",xforms:"http://www.w3.org/2002/01/xforms",saxon:"http://icl.com/saxon",xalan:"http://xml.apache.org/xslt",xsd:"http://www.w3.org/2001/XMLSchema",dt:"http://www.w3.org/2001/XMLSchema-datatypes",xsi:"http://www.w3.org/2001/XMLSchema-instance",rdf:"http://www.w3.org/1999/02/22-rdf-syntax-ns#",rdfs:"http://www.w3.org/2000/01/rdf-schema#",dc:"http://purl.org/dc/elements/1.1/",dcq:"http://purl.org/dc/qualifiers/1.0","soap-env":"http://schemas.xmlsoap.org/soap/envelope/",wsdl:"http://schemas.xmlsoap.org/wsdl/",AdobeExtensions:"http://ns.adobe.com/AdobeSVGViewerExtensions/3.0/"};
dojo.dom.isNode=function(wh){
if(typeof Element=="object"){
try{
return wh instanceof Element;
}
catch(E){
}
}else{
return wh&&!isNaN(wh.nodeType);
}
};
dojo.dom.getTagName=function(node){
dojo.deprecated("dojo.dom.getTagName","use node.tagName instead","0.4");
var _19e=node.tagName;
if(_19e.substr(0,5).toLowerCase()!="dojo:"){
if(_19e.substr(0,4).toLowerCase()=="dojo"){
return "dojo:"+_19e.substring(4).toLowerCase();
}
var djt=node.getAttribute("dojoType")||node.getAttribute("dojotype");
if(djt){
return "dojo:"+djt.toLowerCase();
}
if((node.getAttributeNS)&&(node.getAttributeNS(this.dojoml,"type"))){
return "dojo:"+node.getAttributeNS(this.dojoml,"type").toLowerCase();
}
try{
djt=node.getAttribute("dojo:type");
}
catch(e){
}
if(djt){
return "dojo:"+djt.toLowerCase();
}
if((!dj_global["djConfig"])||(!djConfig["ignoreClassNames"])){
var _1a0=node.className||node.getAttribute("class");
if((_1a0)&&(_1a0.indexOf)&&(_1a0.indexOf("dojo-")!=-1)){
var _1a1=_1a0.split(" ");
for(var x=0;x<_1a1.length;x++){
if((_1a1[x].length>5)&&(_1a1[x].indexOf("dojo-")>=0)){
return "dojo:"+_1a1[x].substr(5).toLowerCase();
}
}
}
}
}
return _19e.toLowerCase();
};
dojo.dom.getUniqueId=function(){
do{
var id="dj_unique_"+(++arguments.callee._idIncrement);
}while(document.getElementById(id));
return id;
};
dojo.dom.getUniqueId._idIncrement=0;
dojo.dom.firstElement=dojo.dom.getFirstChildElement=function(_1a4,_1a5){
var node=_1a4.firstChild;
while(node&&node.nodeType!=dojo.dom.ELEMENT_NODE){
node=node.nextSibling;
}
if(_1a5&&node&&node.tagName&&node.tagName.toLowerCase()!=_1a5.toLowerCase()){
node=dojo.dom.nextElement(node,_1a5);
}
return node;
};
dojo.dom.lastElement=dojo.dom.getLastChildElement=function(_1a7,_1a8){
var node=_1a7.lastChild;
while(node&&node.nodeType!=dojo.dom.ELEMENT_NODE){
node=node.previousSibling;
}
if(_1a8&&node&&node.tagName&&node.tagName.toLowerCase()!=_1a8.toLowerCase()){
node=dojo.dom.prevElement(node,_1a8);
}
return node;
};
dojo.dom.nextElement=dojo.dom.getNextSiblingElement=function(node,_1ab){
if(!node){
return null;
}
do{
node=node.nextSibling;
}while(node&&node.nodeType!=dojo.dom.ELEMENT_NODE);
if(node&&_1ab&&_1ab.toLowerCase()!=node.tagName.toLowerCase()){
return dojo.dom.nextElement(node,_1ab);
}
return node;
};
dojo.dom.prevElement=dojo.dom.getPreviousSiblingElement=function(node,_1ad){
if(!node){
return null;
}
if(_1ad){
_1ad=_1ad.toLowerCase();
}
do{
node=node.previousSibling;
}while(node&&node.nodeType!=dojo.dom.ELEMENT_NODE);
if(node&&_1ad&&_1ad.toLowerCase()!=node.tagName.toLowerCase()){
return dojo.dom.prevElement(node,_1ad);
}
return node;
};
dojo.dom.moveChildren=function(_1ae,_1af,trim){
var _1b1=0;
if(trim){
while(_1ae.hasChildNodes()&&_1ae.firstChild.nodeType==dojo.dom.TEXT_NODE){
_1ae.removeChild(_1ae.firstChild);
}
while(_1ae.hasChildNodes()&&_1ae.lastChild.nodeType==dojo.dom.TEXT_NODE){
_1ae.removeChild(_1ae.lastChild);
}
}
while(_1ae.hasChildNodes()){
_1af.appendChild(_1ae.firstChild);
_1b1++;
}
return _1b1;
};
dojo.dom.copyChildren=function(_1b2,_1b3,trim){
var _1b5=_1b2.cloneNode(true);
return this.moveChildren(_1b5,_1b3,trim);
};
dojo.dom.removeChildren=function(node){
var _1b7=node.childNodes.length;
while(node.hasChildNodes()){
node.removeChild(node.firstChild);
}
return _1b7;
};
dojo.dom.replaceChildren=function(node,_1b9){
dojo.dom.removeChildren(node);
node.appendChild(_1b9);
};
dojo.dom.removeNode=function(node){
if(node&&node.parentNode){
return node.parentNode.removeChild(node);
}
};
dojo.dom.getAncestors=function(node,_1bc,_1bd){
var _1be=[];
var _1bf=dojo.lang.isFunction(_1bc);
while(node){
if(!_1bf||_1bc(node)){
_1be.push(node);
}
if(_1bd&&_1be.length>0){
return _1be[0];
}
node=node.parentNode;
}
if(_1bd){
return null;
}
return _1be;
};
dojo.dom.getAncestorsByTag=function(node,tag,_1c2){
tag=tag.toLowerCase();
return dojo.dom.getAncestors(node,function(el){
return ((el.tagName)&&(el.tagName.toLowerCase()==tag));
},_1c2);
};
dojo.dom.getFirstAncestorByTag=function(node,tag){
return dojo.dom.getAncestorsByTag(node,tag,true);
};
dojo.dom.isDescendantOf=function(node,_1c7,_1c8){
if(_1c8&&node){
node=node.parentNode;
}
while(node){
if(node==_1c7){
return true;
}
node=node.parentNode;
}
return false;
};
dojo.dom.innerXML=function(node){
if(node.innerXML){
return node.innerXML;
}else{
if(node.xml){
return node.xml;
}else{
if(typeof XMLSerializer!="undefined"){
return (new XMLSerializer()).serializeToString(node);
}
}
}
};
dojo.dom.createDocument=function(){
var doc=null;
if(!dj_undef("ActiveXObject")){
var _1cb=["MSXML2","Microsoft","MSXML","MSXML3"];
for(var i=0;i<_1cb.length;i++){
try{
doc=new ActiveXObject(_1cb[i]+".XMLDOM");
}
catch(e){
}
if(doc){
break;
}
}
}else{
if((document.implementation)&&(document.implementation.createDocument)){
doc=document.implementation.createDocument("","",null);
}
}
return doc;
};
dojo.dom.createDocumentFromText=function(str,_1ce){
if(!_1ce){
_1ce="text/xml";
}
if(!dj_undef("DOMParser")){
var _1cf=new DOMParser();
return _1cf.parseFromString(str,_1ce);
}else{
if(!dj_undef("ActiveXObject")){
var _1d0=dojo.dom.createDocument();
if(_1d0){
_1d0.async=false;
_1d0.loadXML(str);
return _1d0;
}else{
dojo.debug("toXml didn't work?");
}
}else{
if(document.createElement){
var tmp=document.createElement("xml");
tmp.innerHTML=str;
if(document.implementation&&document.implementation.createDocument){
var _1d2=document.implementation.createDocument("foo","",null);
for(var i=0;i<tmp.childNodes.length;i++){
_1d2.importNode(tmp.childNodes.item(i),true);
}
return _1d2;
}
return ((tmp.document)&&(tmp.document.firstChild?tmp.document.firstChild:tmp));
}
}
}
return null;
};
dojo.dom.prependChild=function(node,_1d5){
if(_1d5.firstChild){
_1d5.insertBefore(node,_1d5.firstChild);
}else{
_1d5.appendChild(node);
}
return true;
};
dojo.dom.insertBefore=function(node,ref,_1d8){
if(_1d8!=true&&(node===ref||node.nextSibling===ref)){
return false;
}
var _1d9=ref.parentNode;
_1d9.insertBefore(node,ref);
return true;
};
dojo.dom.insertAfter=function(node,ref,_1dc){
var pn=ref.parentNode;
if(ref==pn.lastChild){
if((_1dc!=true)&&(node===ref)){
return false;
}
pn.appendChild(node);
}else{
return this.insertBefore(node,ref.nextSibling,_1dc);
}
return true;
};
dojo.dom.insertAtPosition=function(node,ref,_1e0){
if((!node)||(!ref)||(!_1e0)){
return false;
}
switch(_1e0.toLowerCase()){
case "before":
return dojo.dom.insertBefore(node,ref);
case "after":
return dojo.dom.insertAfter(node,ref);
case "first":
if(ref.firstChild){
return dojo.dom.insertBefore(node,ref.firstChild);
}else{
ref.appendChild(node);
return true;
}
break;
default:
ref.appendChild(node);
return true;
}
};
dojo.dom.insertAtIndex=function(node,_1e2,_1e3){
var _1e4=_1e2.childNodes;
if(!_1e4.length){
_1e2.appendChild(node);
return true;
}
var _1e5=null;
for(var i=0;i<_1e4.length;i++){
var _1e7=_1e4.item(i)["getAttribute"]?parseInt(_1e4.item(i).getAttribute("dojoinsertionindex")):-1;
if(_1e7<_1e3){
_1e5=_1e4.item(i);
}
}
if(_1e5){
return dojo.dom.insertAfter(node,_1e5);
}else{
return dojo.dom.insertBefore(node,_1e4.item(0));
}
};
dojo.dom.textContent=function(node,text){
if(text){
dojo.dom.replaceChildren(node,document.createTextNode(text));
return text;
}else{
var _1ea="";
if(node==null){
return _1ea;
}
for(var i=0;i<node.childNodes.length;i++){
switch(node.childNodes[i].nodeType){
case 1:
case 5:
_1ea+=dojo.dom.textContent(node.childNodes[i]);
break;
case 3:
case 2:
case 4:
_1ea+=node.childNodes[i].nodeValue;
break;
default:
break;
}
}
return _1ea;
}
};
dojo.dom.collectionToArray=function(_1ec){
dojo.deprecated("dojo.dom.collectionToArray","use dojo.lang.toArray instead","0.4");
return dojo.lang.toArray(_1ec);
};
dojo.dom.hasParent=function(node){
return node&&node.parentNode&&dojo.dom.isNode(node.parentNode);
};
dojo.dom.isTag=function(node){
if(node&&node.tagName){
var arr=dojo.lang.toArray(arguments,1);
return arr[dojo.lang.find(node.tagName,arr)]||"";
}
return "";
};
dojo.provide("dojo.undo.browser");
dojo.require("dojo.io");
try{
if((!djConfig["preventBackButtonFix"])&&(!dojo.hostenv.post_load_)){
document.write("<iframe style='border: 0px; width: 1px; height: 1px; position: absolute; bottom: 0px; right: 0px; visibility: visible;' name='djhistory' id='djhistory' src='"+(dojo.hostenv.getBaseScriptUri()+"iframe_history.html")+"'></iframe>");
}
}
catch(e){
}
if(dojo.render.html.opera){
dojo.debug("Opera is not supported with dojo.undo.browser, so back/forward detection will not work.");
}
dojo.undo.browser={initialHref:window.location.href,initialHash:window.location.hash,moveForward:false,historyStack:[],forwardStack:[],historyIframe:null,bookmarkAnchor:null,locationTimer:null,setInitialState:function(args){
this.initialState={"url":this.initialHref,"kwArgs":args,"urlHash":this.initialHash};
},addToHistory:function(args){
var hash=null;
if(!this.historyIframe){
this.historyIframe=window.frames["djhistory"];
}
if(!this.bookmarkAnchor){
this.bookmarkAnchor=document.createElement("a");
(document.body||document.getElementsByTagName("body")[0]).appendChild(this.bookmarkAnchor);
this.bookmarkAnchor.style.display="none";
}
if((!args["changeUrl"])||(dojo.render.html.ie)){
var url=dojo.hostenv.getBaseScriptUri()+"iframe_history.html?"+(new Date()).getTime();
this.moveForward=true;
dojo.io.setIFrameSrc(this.historyIframe,url,false);
}
if(args["changeUrl"]){
this.changingUrl=true;
hash="#"+((args["changeUrl"]!==true)?args["changeUrl"]:(new Date()).getTime());
setTimeout("window.location.href = '"+hash+"'; dojo.undo.browser.changingUrl = false;",1);
this.bookmarkAnchor.href=hash;
if(dojo.render.html.ie){
var _1f4=args["back"]||args["backButton"]||args["handle"];
var tcb=function(_1f6){
if(window.location.hash!=""){
setTimeout("window.location.href = '"+hash+"';",1);
}
_1f4.apply(this,[_1f6]);
};
if(args["back"]){
args.back=tcb;
}else{
if(args["backButton"]){
args.backButton=tcb;
}else{
if(args["handle"]){
args.handle=tcb;
}
}
}
this.forwardStack=[];
var _1f7=args["forward"]||args["forwardButton"]||args["handle"];
var tfw=function(_1f9){
if(window.location.hash!=""){
window.location.href=hash;
}
if(_1f7){
_1f7.apply(this,[_1f9]);
}
};
if(args["forward"]){
args.forward=tfw;
}else{
if(args["forwardButton"]){
args.forwardButton=tfw;
}else{
if(args["handle"]){
args.handle=tfw;
}
}
}
}else{
if(dojo.render.html.moz){
if(!this.locationTimer){
this.locationTimer=setInterval("dojo.undo.browser.checkLocation();",200);
}
}
}
}
this.historyStack.push({"url":url,"kwArgs":args,"urlHash":hash});
},checkLocation:function(){
if(!this.changingUrl){
var hsl=this.historyStack.length;
if((window.location.hash==this.initialHash||window.location.href==this.initialHref)&&(hsl==1)){
this.handleBackButton();
return;
}
if(this.forwardStack.length>0){
if(this.forwardStack[this.forwardStack.length-1].urlHash==window.location.hash){
this.handleForwardButton();
return;
}
}
if((hsl>=2)&&(this.historyStack[hsl-2])){
if(this.historyStack[hsl-2].urlHash==window.location.hash){
this.handleBackButton();
return;
}
}
}
},iframeLoaded:function(evt,_1fc){
if(!dojo.render.html.opera){
var _1fd=this._getUrlQuery(_1fc.href);
if(_1fd==null){
if(this.historyStack.length==1){
this.handleBackButton();
}
return;
}
if(this.moveForward){
this.moveForward=false;
return;
}
if(this.historyStack.length>=2&&_1fd==this._getUrlQuery(this.historyStack[this.historyStack.length-2].url)){
this.handleBackButton();
}else{
if(this.forwardStack.length>0&&_1fd==this._getUrlQuery(this.forwardStack[this.forwardStack.length-1].url)){
this.handleForwardButton();
}
}
}
},handleBackButton:function(){
var _1fe=this.historyStack.pop();
if(!_1fe){
return;
}
var last=this.historyStack[this.historyStack.length-1];
if(!last&&this.historyStack.length==0){
last=this.initialState;
}
if(last){
if(last.kwArgs["back"]){
last.kwArgs["back"]();
}else{
if(last.kwArgs["backButton"]){
last.kwArgs["backButton"]();
}else{
if(last.kwArgs["handle"]){
last.kwArgs.handle("back");
}
}
}
}
this.forwardStack.push(_1fe);
},handleForwardButton:function(){
var last=this.forwardStack.pop();
if(!last){
return;
}
if(last.kwArgs["forward"]){
last.kwArgs.forward();
}else{
if(last.kwArgs["forwardButton"]){
last.kwArgs.forwardButton();
}else{
if(last.kwArgs["handle"]){
last.kwArgs.handle("forward");
}
}
}
this.historyStack.push(last);
},_getUrlQuery:function(url){
var _202=url.split("?");
if(_202.length<2){
return null;
}else{
return _202[1];
}
}};
dojo.provide("dojo.io.BrowserIO");
dojo.require("dojo.io");
dojo.require("dojo.lang.array");
dojo.require("dojo.lang.func");
dojo.require("dojo.string.extras");
dojo.require("dojo.dom");
dojo.require("dojo.undo.browser");
dojo.io.checkChildrenForFile=function(node){
var _204=false;
var _205=node.getElementsByTagName("input");
dojo.lang.forEach(_205,function(_206){
if(_204){
return;
}
if(_206.getAttribute("type")=="file"){
_204=true;
}
});
return _204;
};
dojo.io.formHasFile=function(_207){
return dojo.io.checkChildrenForFile(_207);
};
dojo.io.updateNode=function(node,_209){
node=dojo.byId(node);
var args=_209;
if(dojo.lang.isString(_209)){
args={url:_209};
}
args.mimetype="text/html";
args.load=function(t,d,e){
while(node.firstChild){
if(dojo["event"]){
try{
dojo.event.browser.clean(node.firstChild);
}
catch(e){
}
}
node.removeChild(node.firstChild);
}
node.innerHTML=d;
};
dojo.io.bind(args);
};
dojo.io.formFilter=function(node){
var type=(node.type||"").toLowerCase();
return !node.disabled&&node.name&&!dojo.lang.inArray(type,["file","submit","image","reset","button"]);
};
dojo.io.encodeForm=function(_210,_211,_212){
if((!_210)||(!_210.tagName)||(!_210.tagName.toLowerCase()=="form")){
dojo.raise("Attempted to encode a non-form element.");
}
if(!_212){
_212=dojo.io.formFilter;
}
var enc=/utf/i.test(_211||"")?encodeURIComponent:dojo.string.encodeAscii;
var _214=[];
for(var i=0;i<_210.elements.length;i++){
var elm=_210.elements[i];
if(!elm||elm.tagName.toLowerCase()=="fieldset"||!_212(elm)){
continue;
}
var name=enc(elm.name);
var type=elm.type.toLowerCase();
if(type=="select-multiple"){
for(var j=0;j<elm.options.length;j++){
if(elm.options[j].selected){
_214.push(name+"="+enc(elm.options[j].value));
}
}
}else{
if(dojo.lang.inArray(type,["radio","checkbox"])){
if(elm.checked){
_214.push(name+"="+enc(elm.value));
}
}else{
_214.push(name+"="+enc(elm.value));
}
}
}
var _21a=_210.getElementsByTagName("input");
for(var i=0;i<_21a.length;i++){
var _21b=_21a[i];
if(_21b.type.toLowerCase()=="image"&&_21b.form==_210&&_212(_21b)){
var name=enc(_21b.name);
_214.push(name+"="+enc(_21b.value));
_214.push(name+".x=0");
_214.push(name+".y=0");
}
}
return _214.join("&")+"&";
};
dojo.io.FormBind=function(args){
this.bindArgs={};
if(args&&args.formNode){
this.init(args);
}else{
if(args){
this.init({formNode:args});
}
}
};
dojo.lang.extend(dojo.io.FormBind,{form:null,bindArgs:null,clickedButton:null,init:function(args){
var form=dojo.byId(args.formNode);
if(!form||!form.tagName||form.tagName.toLowerCase()!="form"){
throw new Error("FormBind: Couldn't apply, invalid form");
}else{
if(this.form==form){
return;
}else{
if(this.form){
throw new Error("FormBind: Already applied to a form");
}
}
}
dojo.lang.mixin(this.bindArgs,args);
this.form=form;
this.connect(form,"onsubmit","submit");
for(var i=0;i<form.elements.length;i++){
var node=form.elements[i];
if(node&&node.type&&dojo.lang.inArray(node.type.toLowerCase(),["submit","button"])){
this.connect(node,"onclick","click");
}
}
var _221=form.getElementsByTagName("input");
for(var i=0;i<_221.length;i++){
var _222=_221[i];
if(_222.type.toLowerCase()=="image"&&_222.form==form){
this.connect(_222,"onclick","click");
}
}
},onSubmit:function(form){
return true;
},submit:function(e){
e.preventDefault();
if(this.onSubmit(this.form)){
dojo.io.bind(dojo.lang.mixin(this.bindArgs,{formFilter:dojo.lang.hitch(this,"formFilter")}));
}
},click:function(e){
var node=e.currentTarget;
if(node.disabled){
return;
}
this.clickedButton=node;
},formFilter:function(node){
var type=(node.type||"").toLowerCase();
var _229=false;
if(node.disabled||!node.name){
_229=false;
}else{
if(dojo.lang.inArray(type,["submit","button","image"])){
if(!this.clickedButton){
this.clickedButton=node;
}
_229=node==this.clickedButton;
}else{
_229=!dojo.lang.inArray(type,["file","submit","reset","button"]);
}
}
return _229;
},connect:function(_22a,_22b,_22c){
if(dojo.evalObjPath("dojo.event.connect")){
dojo.event.connect(_22a,_22b,this,_22c);
}else{
var fcn=dojo.lang.hitch(this,_22c);
_22a[_22b]=function(e){
if(!e){
e=window.event;
}
if(!e.currentTarget){
e.currentTarget=e.srcElement;
}
if(!e.preventDefault){
e.preventDefault=function(){
window.event.returnValue=false;
};
}
fcn(e);
};
}
}});
dojo.io.XMLHTTPTransport=new function(){
var _22f=this;
var _230={};
this.useCache=false;
this.preventCache=false;
function getCacheKey(url,_232,_233){
return url+"|"+_232+"|"+_233.toLowerCase();
}
function addToCache(url,_235,_236,http){
_230[getCacheKey(url,_235,_236)]=http;
}
function getFromCache(url,_239,_23a){
return _230[getCacheKey(url,_239,_23a)];
}
this.clearCache=function(){
_230={};
};
function doLoad(_23b,http,url,_23e,_23f){
if(((http.status>=200)&&(http.status<300))||(http.status==304)||(location.protocol=="file:"&&(http.status==0||http.status==undefined))||(location.protocol=="chrome:"&&(http.status==0||http.status==undefined))){
var ret;
if(_23b.method.toLowerCase()=="head"){
var _241=http.getAllResponseHeaders();
ret={};
ret.toString=function(){
return _241;
};
var _242=_241.split(/[\r\n]+/g);
for(var i=0;i<_242.length;i++){
var pair=_242[i].match(/^([^:]+)\s*:\s*(.+)$/i);
if(pair){
ret[pair[1]]=pair[2];
}
}
}else{
if(_23b.mimetype=="text/javascript"){
try{
ret=dj_eval(http.responseText);
}
catch(e){
dojo.debug(e);
dojo.debug(http.responseText);
ret=null;
}
}else{
if(_23b.mimetype=="text/json"){
try{
ret=dj_eval("("+http.responseText+")");
}
catch(e){
dojo.debug(e);
dojo.debug(http.responseText);
ret=false;
}
}else{
if((_23b.mimetype=="application/xml")||(_23b.mimetype=="text/xml")){
ret=http.responseXML;
if(!ret||typeof ret=="string"||!http.getResponseHeader("Content-Type")){
ret=dojo.dom.createDocumentFromText(http.responseText);
}
}else{
ret=http.responseText;
}
}
}
}
if(_23f){
addToCache(url,_23e,_23b.method,http);
}
_23b[(typeof _23b.load=="function")?"load":"handle"]("load",ret,http,_23b);
}else{
var _245=new dojo.io.Error("XMLHttpTransport Error: "+http.status+" "+http.statusText);
_23b[(typeof _23b.error=="function")?"error":"handle"]("error",_245,http,_23b);
}
}
function setHeaders(http,_247){
if(_247["headers"]){
for(var _248 in _247["headers"]){
if(_248.toLowerCase()=="content-type"&&!_247["contentType"]){
_247["contentType"]=_247["headers"][_248];
}else{
http.setRequestHeader(_248,_247["headers"][_248]);
}
}
}
}
this.inFlight=[];
this.inFlightTimer=null;
this.startWatchingInFlight=function(){
if(!this.inFlightTimer){
this.inFlightTimer=setInterval("dojo.io.XMLHTTPTransport.watchInFlight();",10);
}
};
this.watchInFlight=function(){
var now=null;
for(var x=this.inFlight.length-1;x>=0;x--){
var tif=this.inFlight[x];
if(!tif){
this.inFlight.splice(x,1);
continue;
}
if(4==tif.http.readyState){
this.inFlight.splice(x,1);
doLoad(tif.req,tif.http,tif.url,tif.query,tif.useCache);
}else{
if(tif.startTime){
if(!now){
now=(new Date()).getTime();
}
if(tif.startTime+(tif.req.timeoutSeconds*1000)<now){
if(typeof tif.http.abort=="function"){
tif.http.abort();
}
this.inFlight.splice(x,1);
tif.req[(typeof tif.req.timeout=="function")?"timeout":"handle"]("timeout",null,tif.http,tif.req);
}
}
}
}
if(this.inFlight.length==0){
clearInterval(this.inFlightTimer);
this.inFlightTimer=null;
}
};
var _24c=dojo.hostenv.getXmlhttpObject()?true:false;
this.canHandle=function(_24d){
return _24c&&dojo.lang.inArray((_24d["mimetype"].toLowerCase()||""),["text/plain","text/html","application/xml","text/xml","text/javascript","text/json"])&&!(_24d["formNode"]&&dojo.io.formHasFile(_24d["formNode"]));
};
this.multipartBoundary="45309FFF-BD65-4d50-99C9-36986896A96F";
this.bind=function(_24e){
if(!_24e["url"]){
if(!_24e["formNode"]&&(_24e["backButton"]||_24e["back"]||_24e["changeUrl"]||_24e["watchForURL"])&&(!djConfig.preventBackButtonFix)){
dojo.deprecated("Using dojo.io.XMLHTTPTransport.bind() to add to browser history without doing an IO request","Use dojo.undo.browser.addToHistory() instead.","0.4");
dojo.undo.browser.addToHistory(_24e);
return true;
}
}
var url=_24e.url;
var _250="";
if(_24e["formNode"]){
var ta=_24e.formNode.getAttribute("action");
if((ta)&&(!_24e["url"])){
url=ta;
}
var tp=_24e.formNode.getAttribute("method");
if((tp)&&(!_24e["method"])){
_24e.method=tp;
}
_250+=dojo.io.encodeForm(_24e.formNode,_24e.encoding,_24e["formFilter"]);
}
if(url.indexOf("#")>-1){
dojo.debug("Warning: dojo.io.bind: stripping hash values from url:",url);
url=url.split("#")[0];
}
if(_24e["file"]){
_24e.method="post";
}
if(!_24e["method"]){
_24e.method="get";
}
if(_24e.method.toLowerCase()=="get"){
_24e.multipart=false;
}else{
if(_24e["file"]){
_24e.multipart=true;
}else{
if(!_24e["multipart"]){
_24e.multipart=false;
}
}
}
if(_24e["backButton"]||_24e["back"]||_24e["changeUrl"]){
dojo.undo.browser.addToHistory(_24e);
}
var _253=_24e["content"]||{};
if(_24e.sendTransport){
_253["dojo.transport"]="xmlhttp";
}
do{
if(_24e.postContent){
_250=_24e.postContent;
break;
}
if(_253){
_250+=dojo.io.argsFromMap(_253,_24e.encoding);
}
if(_24e.method.toLowerCase()=="get"||!_24e.multipart){
break;
}
var t=[];
if(_250.length){
var q=_250.split("&");
for(var i=0;i<q.length;++i){
if(q[i].length){
var p=q[i].split("=");
t.push("--"+this.multipartBoundary,"Content-Disposition: form-data; name=\""+p[0]+"\"","",p[1]);
}
}
}
if(_24e.file){
if(dojo.lang.isArray(_24e.file)){
for(var i=0;i<_24e.file.length;++i){
var o=_24e.file[i];
t.push("--"+this.multipartBoundary,"Content-Disposition: form-data; name=\""+o.name+"\"; filename=\""+("fileName" in o?o.fileName:o.name)+"\"","Content-Type: "+("contentType" in o?o.contentType:"application/octet-stream"),"",o.content);
}
}else{
var o=_24e.file;
t.push("--"+this.multipartBoundary,"Content-Disposition: form-data; name=\""+o.name+"\"; filename=\""+("fileName" in o?o.fileName:o.name)+"\"","Content-Type: "+("contentType" in o?o.contentType:"application/octet-stream"),"",o.content);
}
}
if(t.length){
t.push("--"+this.multipartBoundary+"--","");
_250=t.join("\r\n");
}
}while(false);
var _259=_24e["sync"]?false:true;
var _25a=_24e["preventCache"]||(this.preventCache==true&&_24e["preventCache"]!=false);
var _25b=_24e["useCache"]==true||(this.useCache==true&&_24e["useCache"]!=false);
if(!_25a&&_25b){
var _25c=getFromCache(url,_250,_24e.method);
if(_25c){
doLoad(_24e,_25c,url,_250,false);
return;
}
}
var http=dojo.hostenv.getXmlhttpObject(_24e);
var _25e=false;
if(_259){
var _25f=this.inFlight.push({"req":_24e,"http":http,"url":url,"query":_250,"useCache":_25b,"startTime":_24e.timeoutSeconds?(new Date()).getTime():0});
this.startWatchingInFlight();
}
if(_24e.method.toLowerCase()=="post"){
http.open("POST",url,_259);
setHeaders(http,_24e);
http.setRequestHeader("Content-Type",_24e.multipart?("multipart/form-data; boundary="+this.multipartBoundary):(_24e.contentType||"application/x-www-form-urlencoded"));
try{
http.send(_250);
}
catch(e){
if(typeof http.abort=="function"){
http.abort();
}
doLoad(_24e,{status:404},url,_250,_25b);
}
}else{
var _260=url;
if(_250!=""){
_260+=(_260.indexOf("?")>-1?"&":"?")+_250;
}
if(_25a){
_260+=(dojo.string.endsWithAny(_260,"?","&")?"":(_260.indexOf("?")>-1?"&":"?"))+"dojo.preventCache="+new Date().valueOf();
}
http.open(_24e.method.toUpperCase(),_260,_259);
setHeaders(http,_24e);
try{
http.send(null);
}
catch(e){
if(typeof http.abort=="function"){
http.abort();
}
doLoad(_24e,{status:404},url,_250,_25b);
}
}
if(!_259){
doLoad(_24e,http,url,_250,_25b);
}
_24e.abort=function(){
return http.abort();
};
return;
};
dojo.io.transports.addTransport("XMLHTTPTransport");
};
dojo.provide("dojo.event");
dojo.require("dojo.lang.array");
dojo.require("dojo.lang.extras");
dojo.require("dojo.lang.func");
dojo.event=new function(){
this.canTimeout=dojo.lang.isFunction(dj_global["setTimeout"])||dojo.lang.isAlien(dj_global["setTimeout"]);
function interpolateArgs(args,_262){
var dl=dojo.lang;
var ao={srcObj:dj_global,srcFunc:null,adviceObj:dj_global,adviceFunc:null,aroundObj:null,aroundFunc:null,adviceType:(args.length>2)?args[0]:"after",precedence:"last",once:false,delay:null,rate:0,adviceMsg:false};
switch(args.length){
case 0:
return;
case 1:
return;
case 2:
ao.srcFunc=args[0];
ao.adviceFunc=args[1];
break;
case 3:
if((dl.isObject(args[0]))&&(dl.isString(args[1]))&&(dl.isString(args[2]))){
ao.adviceType="after";
ao.srcObj=args[0];
ao.srcFunc=args[1];
ao.adviceFunc=args[2];
}else{
if((dl.isString(args[1]))&&(dl.isString(args[2]))){
ao.srcFunc=args[1];
ao.adviceFunc=args[2];
}else{
if((dl.isObject(args[0]))&&(dl.isString(args[1]))&&(dl.isFunction(args[2]))){
ao.adviceType="after";
ao.srcObj=args[0];
ao.srcFunc=args[1];
var _265=dl.nameAnonFunc(args[2],ao.adviceObj,_262);
ao.adviceFunc=_265;
}else{
if((dl.isFunction(args[0]))&&(dl.isObject(args[1]))&&(dl.isString(args[2]))){
ao.adviceType="after";
ao.srcObj=dj_global;
var _265=dl.nameAnonFunc(args[0],ao.srcObj,_262);
ao.srcFunc=_265;
ao.adviceObj=args[1];
ao.adviceFunc=args[2];
}
}
}
}
break;
case 4:
if((dl.isObject(args[0]))&&(dl.isObject(args[2]))){
ao.adviceType="after";
ao.srcObj=args[0];
ao.srcFunc=args[1];
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
if((dl.isString(args[0]))&&(dl.isString(args[1]))&&(dl.isObject(args[2]))){
ao.adviceType=args[0];
ao.srcObj=dj_global;
ao.srcFunc=args[1];
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
if((dl.isString(args[0]))&&(dl.isFunction(args[1]))&&(dl.isObject(args[2]))){
ao.adviceType=args[0];
ao.srcObj=dj_global;
var _265=dl.nameAnonFunc(args[1],dj_global,_262);
ao.srcFunc=_265;
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
if((dl.isString(args[0]))&&(dl.isObject(args[1]))&&(dl.isString(args[2]))&&(dl.isFunction(args[3]))){
ao.srcObj=args[1];
ao.srcFunc=args[2];
var _265=dl.nameAnonFunc(args[3],dj_global,_262);
ao.adviceObj=dj_global;
ao.adviceFunc=_265;
}else{
if(dl.isObject(args[1])){
ao.srcObj=args[1];
ao.srcFunc=args[2];
ao.adviceObj=dj_global;
ao.adviceFunc=args[3];
}else{
if(dl.isObject(args[2])){
ao.srcObj=dj_global;
ao.srcFunc=args[1];
ao.adviceObj=args[2];
ao.adviceFunc=args[3];
}else{
ao.srcObj=ao.adviceObj=ao.aroundObj=dj_global;
ao.srcFunc=args[1];
ao.adviceFunc=args[2];
ao.aroundFunc=args[3];
}
}
}
}
}
}
break;
case 6:
ao.srcObj=args[1];
ao.srcFunc=args[2];
ao.adviceObj=args[3];
ao.adviceFunc=args[4];
ao.aroundFunc=args[5];
ao.aroundObj=dj_global;
break;
default:
ao.srcObj=args[1];
ao.srcFunc=args[2];
ao.adviceObj=args[3];
ao.adviceFunc=args[4];
ao.aroundObj=args[5];
ao.aroundFunc=args[6];
ao.once=args[7];
ao.delay=args[8];
ao.rate=args[9];
ao.adviceMsg=args[10];
break;
}
if(dl.isFunction(ao.aroundFunc)){
var _265=dl.nameAnonFunc(ao.aroundFunc,ao.aroundObj,_262);
ao.aroundFunc=_265;
}
if(dl.isFunction(ao.srcFunc)){
ao.srcFunc=dl.getNameInObj(ao.srcObj,ao.srcFunc);
}
if(dl.isFunction(ao.adviceFunc)){
ao.adviceFunc=dl.getNameInObj(ao.adviceObj,ao.adviceFunc);
}
if((ao.aroundObj)&&(dl.isFunction(ao.aroundFunc))){
ao.aroundFunc=dl.getNameInObj(ao.aroundObj,ao.aroundFunc);
}
if(!ao.srcObj){
dojo.raise("bad srcObj for srcFunc: "+ao.srcFunc);
}
if(!ao.adviceObj){
dojo.raise("bad adviceObj for adviceFunc: "+ao.adviceFunc);
}
return ao;
}
this.connect=function(){
if(arguments.length==1){
var ao=arguments[0];
}else{
var ao=interpolateArgs(arguments,true);
}
if(dojo.lang.isArray(ao.srcObj)&&ao.srcObj!=""){
var _267={};
for(var x in ao){
_267[x]=ao[x];
}
var mjps=[];
dojo.lang.forEach(ao.srcObj,function(src){
if((dojo.render.html.capable)&&(dojo.lang.isString(src))){
src=dojo.byId(src);
}
_267.srcObj=src;
mjps.push(dojo.event.connect.call(dojo.event,_267));
});
return mjps;
}
var mjp=dojo.event.MethodJoinPoint.getForMethod(ao.srcObj,ao.srcFunc);
if(ao.adviceFunc){
var mjp2=dojo.event.MethodJoinPoint.getForMethod(ao.adviceObj,ao.adviceFunc);
}
mjp.kwAddAdvice(ao);
return mjp;
};
this.log=function(a1,a2){
var _26f;
if((arguments.length==1)&&(typeof a1=="object")){
_26f=a1;
}else{
_26f={srcObj:a1,srcFunc:a2};
}
_26f.adviceFunc=function(){
var _270=[];
for(var x=0;x<arguments.length;x++){
_270.push(arguments[x]);
}
dojo.debug("("+_26f.srcObj+")."+_26f.srcFunc,":",_270.join(", "));
};
this.kwConnect(_26f);
};
this.connectBefore=function(){
var args=["before"];
for(var i=0;i<arguments.length;i++){
args.push(arguments[i]);
}
return this.connect.apply(this,args);
};
this.connectAround=function(){
var args=["around"];
for(var i=0;i<arguments.length;i++){
args.push(arguments[i]);
}
return this.connect.apply(this,args);
};
this.connectOnce=function(){
var ao=interpolateArgs(arguments,true);
ao.once=true;
return this.connect(ao);
};
this._kwConnectImpl=function(_277,_278){
var fn=(_278)?"disconnect":"connect";
if(typeof _277["srcFunc"]=="function"){
_277.srcObj=_277["srcObj"]||dj_global;
var _27a=dojo.lang.nameAnonFunc(_277.srcFunc,_277.srcObj,true);
_277.srcFunc=_27a;
}
if(typeof _277["adviceFunc"]=="function"){
_277.adviceObj=_277["adviceObj"]||dj_global;
var _27a=dojo.lang.nameAnonFunc(_277.adviceFunc,_277.adviceObj,true);
_277.adviceFunc=_27a;
}
return dojo.event[fn]((_277["type"]||_277["adviceType"]||"after"),_277["srcObj"]||dj_global,_277["srcFunc"],_277["adviceObj"]||_277["targetObj"]||dj_global,_277["adviceFunc"]||_277["targetFunc"],_277["aroundObj"],_277["aroundFunc"],_277["once"],_277["delay"],_277["rate"],_277["adviceMsg"]||false);
};
this.kwConnect=function(_27b){
return this._kwConnectImpl(_27b,false);
};
this.disconnect=function(){
var ao=interpolateArgs(arguments,true);
if(!ao.adviceFunc){
return;
}
var mjp=dojo.event.MethodJoinPoint.getForMethod(ao.srcObj,ao.srcFunc);
return mjp.removeAdvice(ao.adviceObj,ao.adviceFunc,ao.adviceType,ao.once);
};
this.kwDisconnect=function(_27e){
return this._kwConnectImpl(_27e,true);
};
};
dojo.event.MethodInvocation=function(_27f,obj,args){
this.jp_=_27f;
this.object=obj;
this.args=[];
for(var x=0;x<args.length;x++){
this.args[x]=args[x];
}
this.around_index=-1;
};
dojo.event.MethodInvocation.prototype.proceed=function(){
this.around_index++;
if(this.around_index>=this.jp_.around.length){
return this.jp_.object[this.jp_.methodname].apply(this.jp_.object,this.args);
}else{
var ti=this.jp_.around[this.around_index];
var mobj=ti[0]||dj_global;
var meth=ti[1];
return mobj[meth].call(mobj,this);
}
};
dojo.event.MethodJoinPoint=function(obj,_287){
this.object=obj||dj_global;
this.methodname=_287;
this.methodfunc=this.object[_287];
this.before=[];
this.after=[];
this.around=[];
};
dojo.event.MethodJoinPoint.getForMethod=function(obj,_289){
if(!obj){
obj=dj_global;
}
if(!obj[_289]){
obj[_289]=function(){
};
if(!obj[_289]){
dojo.raise("Cannot set do-nothing method on that object "+_289);
}
}else{
if((!dojo.lang.isFunction(obj[_289]))&&(!dojo.lang.isAlien(obj[_289]))){
return null;
}
}
var _28a=_289+"$joinpoint";
var _28b=_289+"$joinpoint$method";
var _28c=obj[_28a];
if(!_28c){
var _28d=false;
if(dojo.event["browser"]){
if((obj["attachEvent"])||(obj["nodeType"])||(obj["addEventListener"])){
_28d=true;
dojo.event.browser.addClobberNodeAttrs(obj,[_28a,_28b,_289]);
}
}
var _28e=obj[_289].length;
obj[_28b]=obj[_289];
_28c=obj[_28a]=new dojo.event.MethodJoinPoint(obj,_28b);
obj[_289]=function(){
var args=[];
if((_28d)&&(!arguments.length)){
var evt=null;
try{
if(obj.ownerDocument){
evt=obj.ownerDocument.parentWindow.event;
}else{
if(obj.documentElement){
evt=obj.documentElement.ownerDocument.parentWindow.event;
}else{
evt=window.event;
}
}
}
catch(e){
evt=window.event;
}
if(evt){
args.push(dojo.event.browser.fixEvent(evt,this));
}
}else{
for(var x=0;x<arguments.length;x++){
if((x==0)&&(_28d)&&(dojo.event.browser.isEvent(arguments[x]))){
args.push(dojo.event.browser.fixEvent(arguments[x],this));
}else{
args.push(arguments[x]);
}
}
}
return _28c.run.apply(_28c,args);
};
obj[_289].__preJoinArity=_28e;
}
return _28c;
};
dojo.lang.extend(dojo.event.MethodJoinPoint,{unintercept:function(){
this.object[this.methodname]=this.methodfunc;
this.before=[];
this.after=[];
this.around=[];
},disconnect:dojo.lang.forward("unintercept"),run:function(){
var obj=this.object||dj_global;
var args=arguments;
var _294=[];
for(var x=0;x<args.length;x++){
_294[x]=args[x];
}
var _296=function(marr){
if(!marr){
dojo.debug("Null argument to unrollAdvice()");
return;
}
var _298=marr[0]||dj_global;
var _299=marr[1];
if(!_298[_299]){
dojo.raise("function \""+_299+"\" does not exist on \""+_298+"\"");
}
var _29a=marr[2]||dj_global;
var _29b=marr[3];
var msg=marr[6];
var _29d;
var to={args:[],jp_:this,object:obj,proceed:function(){
return _298[_299].apply(_298,to.args);
}};
to.args=_294;
var _29f=parseInt(marr[4]);
var _2a0=((!isNaN(_29f))&&(marr[4]!==null)&&(typeof marr[4]!="undefined"));
if(marr[5]){
var rate=parseInt(marr[5]);
var cur=new Date();
var _2a3=false;
if((marr["last"])&&((cur-marr.last)<=rate)){
if(dojo.event.canTimeout){
if(marr["delayTimer"]){
clearTimeout(marr.delayTimer);
}
var tod=parseInt(rate*2);
var mcpy=dojo.lang.shallowCopy(marr);
marr.delayTimer=setTimeout(function(){
mcpy[5]=0;
_296(mcpy);
},tod);
}
return;
}else{
marr.last=cur;
}
}
if(_29b){
_29a[_29b].call(_29a,to);
}else{
if((_2a0)&&((dojo.render.html)||(dojo.render.svg))){
dj_global["setTimeout"](function(){
if(msg){
_298[_299].call(_298,to);
}else{
_298[_299].apply(_298,args);
}
},_29f);
}else{
if(msg){
_298[_299].call(_298,to);
}else{
_298[_299].apply(_298,args);
}
}
}
};
if(this.before.length>0){
dojo.lang.forEach(this.before,_296);
}
var _2a6;
if(this.around.length>0){
var mi=new dojo.event.MethodInvocation(this,obj,args);
_2a6=mi.proceed();
}else{
if(this.methodfunc){
_2a6=this.object[this.methodname].apply(this.object,args);
}
}
if(this.after.length>0){
dojo.lang.forEach(this.after,_296);
}
return (this.methodfunc)?_2a6:null;
},getArr:function(kind){
var arr=this.after;
if((typeof kind=="string")&&(kind.indexOf("before")!=-1)){
arr=this.before;
}else{
if(kind=="around"){
arr=this.around;
}
}
return arr;
},kwAddAdvice:function(args){
this.addAdvice(args["adviceObj"],args["adviceFunc"],args["aroundObj"],args["aroundFunc"],args["adviceType"],args["precedence"],args["once"],args["delay"],args["rate"],args["adviceMsg"]);
},addAdvice:function(_2ab,_2ac,_2ad,_2ae,_2af,_2b0,once,_2b2,rate,_2b4){
var arr=this.getArr(_2af);
if(!arr){
dojo.raise("bad this: "+this);
}
var ao=[_2ab,_2ac,_2ad,_2ae,_2b2,rate,_2b4];
if(once){
if(this.hasAdvice(_2ab,_2ac,_2af,arr)>=0){
return;
}
}
if(_2b0=="first"){
arr.unshift(ao);
}else{
arr.push(ao);
}
},hasAdvice:function(_2b7,_2b8,_2b9,arr){
if(!arr){
arr=this.getArr(_2b9);
}
var ind=-1;
for(var x=0;x<arr.length;x++){
var aao=(typeof _2b8=="object")?(new String(_2b8)).toString():_2b8;
var a1o=(typeof arr[x][1]=="object")?(new String(arr[x][1])).toString():arr[x][1];
if((arr[x][0]==_2b7)&&(a1o==aao)){
ind=x;
}
}
return ind;
},removeAdvice:function(_2bf,_2c0,_2c1,once){
var arr=this.getArr(_2c1);
var ind=this.hasAdvice(_2bf,_2c0,_2c1,arr);
if(ind==-1){
return false;
}
while(ind!=-1){
arr.splice(ind,1);
if(once){
break;
}
ind=this.hasAdvice(_2bf,_2c0,_2c1,arr);
}
return true;
}});
dojo.require("dojo.event");
dojo.provide("dojo.event.topic");
dojo.event.topic=new function(){
this.topics={};
this.getTopic=function(_2c5){
if(!this.topics[_2c5]){
this.topics[_2c5]=new this.TopicImpl(_2c5);
}
return this.topics[_2c5];
};
this.registerPublisher=function(_2c6,obj,_2c8){
var _2c6=this.getTopic(_2c6);
_2c6.registerPublisher(obj,_2c8);
};
this.subscribe=function(_2c9,obj,_2cb){
var _2c9=this.getTopic(_2c9);
_2c9.subscribe(obj,_2cb);
};
this.unsubscribe=function(_2cc,obj,_2ce){
var _2cc=this.getTopic(_2cc);
_2cc.unsubscribe(obj,_2ce);
};
this.destroy=function(_2cf){
this.getTopic(_2cf).destroy();
delete this.topics[_2cf];
};
this.publishApply=function(_2d0,args){
var _2d0=this.getTopic(_2d0);
_2d0.sendMessage.apply(_2d0,args);
};
this.publish=function(_2d2,_2d3){
var _2d2=this.getTopic(_2d2);
var args=[];
for(var x=1;x<arguments.length;x++){
args.push(arguments[x]);
}
_2d2.sendMessage.apply(_2d2,args);
};
};
dojo.event.topic.TopicImpl=function(_2d6){
this.topicName=_2d6;
this.subscribe=function(_2d7,_2d8){
var tf=_2d8||_2d7;
var to=(!_2d8)?dj_global:_2d7;
dojo.event.kwConnect({srcObj:this,srcFunc:"sendMessage",adviceObj:to,adviceFunc:tf});
};
this.unsubscribe=function(_2db,_2dc){
var tf=(!_2dc)?_2db:_2dc;
var to=(!_2dc)?null:_2db;
dojo.event.kwDisconnect({srcObj:this,srcFunc:"sendMessage",adviceObj:to,adviceFunc:tf});
};
this.destroy=function(){
dojo.event.MethodJoinPoint.getForMethod(this,"sendMessage").disconnect();
};
this.registerPublisher=function(_2df,_2e0){
dojo.event.connect(_2df,_2e0,this,"sendMessage");
};
this.sendMessage=function(_2e1){
};
};
dojo.provide("dojo.event.browser");
dojo.require("dojo.event");
dojo._ie_clobber=new function(){
this.clobberNodes=[];
function nukeProp(node,prop){
try{
node[prop]=null;
}
catch(e){
}
try{
delete node[prop];
}
catch(e){
}
try{
node.removeAttribute(prop);
}
catch(e){
}
}
this.clobber=function(_2e4){
var na;
var tna;
if(_2e4){
tna=_2e4.all||_2e4.getElementsByTagName("*");
na=[_2e4];
for(var x=0;x<tna.length;x++){
if(tna[x]["__doClobber__"]){
na.push(tna[x]);
}
}
}else{
try{
window.onload=null;
}
catch(e){
}
na=(this.clobberNodes.length)?this.clobberNodes:document.all;
}
tna=null;
var _2e8={};
for(var i=na.length-1;i>=0;i=i-1){
var el=na[i];
if(el["__clobberAttrs__"]){
for(var j=0;j<el.__clobberAttrs__.length;j++){
nukeProp(el,el.__clobberAttrs__[j]);
}
nukeProp(el,"__clobberAttrs__");
nukeProp(el,"__doClobber__");
}
}
na=null;
};
};
if(dojo.render.html.ie){
dojo.addOnUnload(function(){
dojo._ie_clobber.clobber();
try{
if((dojo["widget"])&&(dojo.widget["manager"])){
dojo.widget.manager.destroyAll();
}
}
catch(e){
}
try{
window.onload=null;
}
catch(e){
}
try{
window.onunload=null;
}
catch(e){
}
dojo._ie_clobber.clobberNodes=[];
});
}
dojo.event.browser=new function(){
var _2ec=0;
this.clean=function(node){
if(dojo.render.html.ie){
dojo._ie_clobber.clobber(node);
}
};
this.addClobberNode=function(node){
if(!dojo.render.html.ie){
return;
}
if(!node["__doClobber__"]){
node.__doClobber__=true;
dojo._ie_clobber.clobberNodes.push(node);
node.__clobberAttrs__=[];
}
};
this.addClobberNodeAttrs=function(node,_2f0){
if(!dojo.render.html.ie){
return;
}
this.addClobberNode(node);
for(var x=0;x<_2f0.length;x++){
node.__clobberAttrs__.push(_2f0[x]);
}
};
this.removeListener=function(node,_2f3,fp,_2f5){
if(!_2f5){
var _2f5=false;
}
_2f3=_2f3.toLowerCase();
if(_2f3.substr(0,2)=="on"){
_2f3=_2f3.substr(2);
}
if(node.removeEventListener){
node.removeEventListener(_2f3,fp,_2f5);
}
};
this.addListener=function(node,_2f7,fp,_2f9,_2fa){
if(!node){
return;
}
if(!_2f9){
var _2f9=false;
}
_2f7=_2f7.toLowerCase();
if(_2f7.substr(0,2)!="on"){
_2f7="on"+_2f7;
}
if(!_2fa){
var _2fb=function(evt){
if(!evt){
evt=window.event;
}
var ret=fp(dojo.event.browser.fixEvent(evt,this));
if(_2f9){
dojo.event.browser.stopEvent(evt);
}
return ret;
};
}else{
_2fb=fp;
}
if(node.addEventListener){
node.addEventListener(_2f7.substr(2),_2fb,_2f9);
return _2fb;
}else{
if(typeof node[_2f7]=="function"){
var _2fe=node[_2f7];
node[_2f7]=function(e){
_2fe(e);
return _2fb(e);
};
}else{
node[_2f7]=_2fb;
}
if(dojo.render.html.ie){
this.addClobberNodeAttrs(node,[_2f7]);
}
return _2fb;
}
};
this.isEvent=function(obj){
return (typeof obj!="undefined")&&(typeof Event!="undefined")&&(obj.eventPhase);
};
this.currentEvent=null;
this.callListener=function(_301,_302){
if(typeof _301!="function"){
dojo.raise("listener not a function: "+_301);
}
dojo.event.browser.currentEvent.currentTarget=_302;
return _301.call(_302,dojo.event.browser.currentEvent);
};
this.stopPropagation=function(){
dojo.event.browser.currentEvent.cancelBubble=true;
};
this.preventDefault=function(){
dojo.event.browser.currentEvent.returnValue=false;
};
this.keys={KEY_BACKSPACE:8,KEY_TAB:9,KEY_ENTER:13,KEY_SHIFT:16,KEY_CTRL:17,KEY_ALT:18,KEY_PAUSE:19,KEY_CAPS_LOCK:20,KEY_ESCAPE:27,KEY_SPACE:32,KEY_PAGE_UP:33,KEY_PAGE_DOWN:34,KEY_END:35,KEY_HOME:36,KEY_LEFT_ARROW:37,KEY_UP_ARROW:38,KEY_RIGHT_ARROW:39,KEY_DOWN_ARROW:40,KEY_INSERT:45,KEY_DELETE:46,KEY_LEFT_WINDOW:91,KEY_RIGHT_WINDOW:92,KEY_SELECT:93,KEY_F1:112,KEY_F2:113,KEY_F3:114,KEY_F4:115,KEY_F5:116,KEY_F6:117,KEY_F7:118,KEY_F8:119,KEY_F9:120,KEY_F10:121,KEY_F11:122,KEY_F12:123,KEY_NUM_LOCK:144,KEY_SCROLL_LOCK:145};
this.revKeys=[];
for(var key in this.keys){
this.revKeys[this.keys[key]]=key;
}
this.fixEvent=function(evt,_305){
if((!evt)&&(window["event"])){
var evt=window.event;
}
if((evt["type"])&&(evt["type"].indexOf("key")==0)){
evt.keys=this.revKeys;
for(var key in this.keys){
evt[key]=this.keys[key];
}
if((dojo.render.html.ie)&&(evt["type"]=="keypress")){
evt.charCode=evt.keyCode;
}
}
if(dojo.render.html.ie){
if(!evt.target){
evt.target=evt.srcElement;
}
if(!evt.currentTarget){
evt.currentTarget=(_305?_305:evt.srcElement);
}
if(!evt.layerX){
evt.layerX=evt.offsetX;
}
if(!evt.layerY){
evt.layerY=evt.offsetY;
}
var _307=((dojo.render.html.ie55)||(document["compatMode"]=="BackCompat"))?document.body:document.documentElement;
if(!evt.pageX){
evt.pageX=evt.clientX+(_307.scrollLeft||0);
}
if(!evt.pageY){
evt.pageY=evt.clientY+(_307.scrollTop||0);
}
if(evt.type=="mouseover"){
evt.relatedTarget=evt.fromElement;
}
if(evt.type=="mouseout"){
evt.relatedTarget=evt.toElement;
}
this.currentEvent=evt;
evt.callListener=this.callListener;
evt.stopPropagation=this.stopPropagation;
evt.preventDefault=this.preventDefault;
}
return evt;
};
this.stopEvent=function(ev){
if(window.event){
ev.returnValue=false;
ev.cancelBubble=true;
}else{
ev.preventDefault();
ev.stopPropagation();
}
};
};
dojo.kwCompoundRequire({common:["dojo.event","dojo.event.topic"],browser:["dojo.event.browser"],dashboard:["dojo.event.browser"]});
dojo.provide("dojo.event.*");
dojo.provide("dojo.lfx.Animation");
dojo.provide("dojo.lfx.Line");
dojo.require("dojo.lang.func");
dojo.lfx.Line=function(_309,end){
this.start=_309;
this.end=end;
if(dojo.lang.isArray(_309)){
var diff=[];
dojo.lang.forEach(this.start,function(s,i){
diff[i]=this.end[i]-s;
},this);
this.getValue=function(n){
var res=[];
dojo.lang.forEach(this.start,function(s,i){
res[i]=(diff[i]*n)+s;
},this);
return res;
};
}else{
var diff=end-_309;
this.getValue=function(n){
return (diff*n)+this.start;
};
}
};
dojo.lfx.easeIn=function(n){
return Math.pow(n,3);
};
dojo.lfx.easeOut=function(n){
return (1-Math.pow(1-n,3));
};
dojo.lfx.easeInOut=function(n){
return ((3*Math.pow(n,2))-(2*Math.pow(n,3)));
};
dojo.lfx.IAnimation=function(){
};
dojo.lang.extend(dojo.lfx.IAnimation,{curve:null,duration:1000,easing:null,repeatCount:0,rate:25,handler:null,beforeBegin:null,onBegin:null,onAnimate:null,onEnd:null,onPlay:null,onPause:null,onStop:null,play:null,pause:null,stop:null,fire:function(evt,args){
if(this[evt]){
this[evt].apply(this,(args||[]));
}
},_active:false,_paused:false});
dojo.lfx.Animation=function(_318,_319,_31a,_31b,_31c,rate){
dojo.lfx.IAnimation.call(this);
if(dojo.lang.isNumber(_318)||(!_318&&_319.getValue)){
rate=_31c;
_31c=_31b;
_31b=_31a;
_31a=_319;
_319=_318;
_318=null;
}else{
if(_318.getValue||dojo.lang.isArray(_318)){
rate=_31b;
_31c=_31a;
_31b=_319;
_31a=_318;
_319=null;
_318=null;
}
}
if(dojo.lang.isArray(_31a)){
this.curve=new dojo.lfx.Line(_31a[0],_31a[1]);
}else{
this.curve=_31a;
}
if(_319!=null&&_319>0){
this.duration=_319;
}
if(_31c){
this.repeatCount=_31c;
}
if(rate){
this.rate=rate;
}
if(_318){
this.handler=_318.handler;
this.beforeBegin=_318.beforeBegin;
this.onBegin=_318.onBegin;
this.onEnd=_318.onEnd;
this.onPlay=_318.onPlay;
this.onPause=_318.onPause;
this.onStop=_318.onStop;
this.onAnimate=_318.onAnimate;
}
if(_31b&&dojo.lang.isFunction(_31b)){
this.easing=_31b;
}
};
dojo.inherits(dojo.lfx.Animation,dojo.lfx.IAnimation);
dojo.lang.extend(dojo.lfx.Animation,{_startTime:null,_endTime:null,_timer:null,_percent:0,_startRepeatCount:0,play:function(_31e,_31f){
if(_31f){
clearTimeout(this._timer);
this._active=false;
this._paused=false;
this._percent=0;
}else{
if(this._active&&!this._paused){
return this;
}
}
this.fire("handler",["beforeBegin"]);
this.fire("beforeBegin");
if(_31e>0){
setTimeout(dojo.lang.hitch(this,function(){
this.play(null,_31f);
}),_31e);
return this;
}
this._startTime=new Date().valueOf();
if(this._paused){
this._startTime-=(this.duration*this._percent/100);
}
this._endTime=this._startTime+this.duration;
this._active=true;
this._paused=false;
var step=this._percent/100;
var _321=this.curve.getValue(step);
if(this._percent==0){
if(!this._startRepeatCount){
this._startRepeatCount=this.repeatCount;
}
this.fire("handler",["begin",_321]);
this.fire("onBegin",[_321]);
}
this.fire("handler",["play",_321]);
this.fire("onPlay",[_321]);
this._cycle();
return this;
},pause:function(){
clearTimeout(this._timer);
if(!this._active){
return this;
}
this._paused=true;
var _322=this.curve.getValue(this._percent/100);
this.fire("handler",["pause",_322]);
this.fire("onPause",[_322]);
return this;
},gotoPercent:function(pct,_324){
clearTimeout(this._timer);
this._active=true;
this._paused=true;
this._percent=pct;
if(_324){
this.play();
}
},stop:function(_325){
clearTimeout(this._timer);
var step=this._percent/100;
if(_325){
step=1;
}
var _327=this.curve.getValue(step);
this.fire("handler",["stop",_327]);
this.fire("onStop",[_327]);
this._active=false;
this._paused=false;
return this;
},status:function(){
if(this._active){
return this._paused?"paused":"playing";
}else{
return "stopped";
}
},_cycle:function(){
clearTimeout(this._timer);
if(this._active){
var curr=new Date().valueOf();
var step=(curr-this._startTime)/(this._endTime-this._startTime);
if(step>=1){
step=1;
this._percent=100;
}else{
this._percent=step*100;
}
if((this.easing)&&(dojo.lang.isFunction(this.easing))){
step=this.easing(step);
}
var _32a=this.curve.getValue(step);
this.fire("handler",["animate",_32a]);
this.fire("onAnimate",[_32a]);
if(step<1){
this._timer=setTimeout(dojo.lang.hitch(this,"_cycle"),this.rate);
}else{
this._active=false;
this.fire("handler",["end"]);
this.fire("onEnd");
if(this.repeatCount>0){
this.repeatCount--;
this.play(null,true);
}else{
if(this.repeatCount==-1){
this.play(null,true);
}else{
if(this._startRepeatCount){
this.repeatCount=this._startRepeatCount;
this._startRepeatCount=0;
}
}
}
}
}
return this;
}});
dojo.lfx.Combine=function(){
dojo.lfx.IAnimation.call(this);
this._anims=[];
this._animsEnded=0;
var _32b=arguments;
if(_32b.length==1&&(dojo.lang.isArray(_32b[0])||dojo.lang.isArrayLike(_32b[0]))){
_32b=_32b[0];
}
var _32c=this;
dojo.lang.forEach(_32b,function(anim){
_32c._anims.push(anim);
var _32e=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_32e();
_32c._onAnimsEnded();
};
});
};
dojo.inherits(dojo.lfx.Combine,dojo.lfx.IAnimation);
dojo.lang.extend(dojo.lfx.Combine,{_animsEnded:0,play:function(_32f,_330){
if(!this._anims.length){
return this;
}
this.fire("beforeBegin");
if(_32f>0){
setTimeout(dojo.lang.hitch(this,function(){
this.play(null,_330);
}),_32f);
return this;
}
if(_330||this._anims[0].percent==0){
this.fire("onBegin");
}
this.fire("onPlay");
this._animsCall("play",null,_330);
return this;
},pause:function(){
this.fire("onPause");
this._animsCall("pause");
return this;
},stop:function(_331){
this.fire("onStop");
this._animsCall("stop",_331);
return this;
},_onAnimsEnded:function(){
this._animsEnded++;
if(this._animsEnded>=this._anims.length){
this.fire("onEnd");
}
return this;
},_animsCall:function(_332){
var args=[];
if(arguments.length>1){
for(var i=1;i<arguments.length;i++){
args.push(arguments[i]);
}
}
var _335=this;
dojo.lang.forEach(this._anims,function(anim){
anim[_332](args);
},_335);
return this;
}});
dojo.lfx.Chain=function(){
dojo.lfx.IAnimation.call(this);
this._anims=[];
this._currAnim=-1;
var _337=arguments;
if(_337.length==1&&(dojo.lang.isArray(_337[0])||dojo.lang.isArrayLike(_337[0]))){
_337=_337[0];
}
var _338=this;
dojo.lang.forEach(_337,function(anim,i,_33b){
_338._anims.push(anim);
var _33c=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
if(i<_33b.length-1){
anim.onEnd=function(){
_33c();
_338._playNext();
};
}else{
anim.onEnd=function(){
_33c();
_338.fire("onEnd");
};
}
},_338);
};
dojo.inherits(dojo.lfx.Chain,dojo.lfx.IAnimation);
dojo.lang.extend(dojo.lfx.Chain,{_currAnim:-1,play:function(_33d,_33e){
if(!this._anims.length){
return this;
}
if(_33e||!this._anims[this._currAnim]){
this._currAnim=0;
}
var _33f=this._anims[this._currAnim];
this.fire("beforeBegin");
if(_33d>0){
setTimeout(dojo.lang.hitch(this,function(){
this.play(null,_33e);
}),_33d);
return this;
}
if(_33f){
if(this._currAnim==0){
this.fire("handler",["begin",this._currAnim]);
this.fire("onBegin",[this._currAnim]);
}
this.fire("onPlay",[this._currAnim]);
_33f.play(null,_33e);
}
return this;
},pause:function(){
if(this._anims[this._currAnim]){
this._anims[this._currAnim].pause();
this.fire("onPause",[this._currAnim]);
}
return this;
},playPause:function(){
if(this._anims.length==0){
return this;
}
if(this._currAnim==-1){
this._currAnim=0;
}
var _340=this._anims[this._currAnim];
if(_340){
if(!_340._active||_340._paused){
this.play();
}else{
this.pause();
}
}
return this;
},stop:function(){
var _341=this._anims[this._currAnim];
if(_341){
_341.stop();
this.fire("onStop",[this._currAnim]);
}
return _341;
},_playNext:function(){
if(this._currAnim==-1||this._anims.length==0){
return this;
}
this._currAnim++;
if(this._anims[this._currAnim]){
this._anims[this._currAnim].play(null,true);
}
return this;
}});
dojo.lfx.combine=function(){
var _342=arguments;
if(dojo.lang.isArray(arguments[0])){
_342=arguments[0];
}
return new dojo.lfx.Combine(_342);
};
dojo.lfx.chain=function(){
var _343=arguments;
if(dojo.lang.isArray(arguments[0])){
_343=arguments[0];
}
return new dojo.lfx.Chain(_343);
};
dojo.provide("dojo.graphics.color");
dojo.require("dojo.lang.array");
dojo.graphics.color.Color=function(r,g,b,a){
if(dojo.lang.isArray(r)){
this.r=r[0];
this.g=r[1];
this.b=r[2];
this.a=r[3]||1;
}else{
if(dojo.lang.isString(r)){
var rgb=dojo.graphics.color.extractRGB(r);
this.r=rgb[0];
this.g=rgb[1];
this.b=rgb[2];
this.a=g||1;
}else{
if(r instanceof dojo.graphics.color.Color){
this.r=r.r;
this.b=r.b;
this.g=r.g;
this.a=r.a;
}else{
this.r=r;
this.g=g;
this.b=b;
this.a=a;
}
}
}
};
dojo.graphics.color.Color.fromArray=function(arr){
return new dojo.graphics.color.Color(arr[0],arr[1],arr[2],arr[3]);
};
dojo.lang.extend(dojo.graphics.color.Color,{toRgb:function(_34a){
if(_34a){
return this.toRgba();
}else{
return [this.r,this.g,this.b];
}
},toRgba:function(){
return [this.r,this.g,this.b,this.a];
},toHex:function(){
return dojo.graphics.color.rgb2hex(this.toRgb());
},toCss:function(){
return "rgb("+this.toRgb().join()+")";
},toString:function(){
return this.toHex();
},blend:function(_34b,_34c){
return dojo.graphics.color.blend(this.toRgb(),new dojo.graphics.color.Color(_34b).toRgb(),_34c);
}});
dojo.graphics.color.named={white:[255,255,255],black:[0,0,0],red:[255,0,0],green:[0,255,0],blue:[0,0,255],navy:[0,0,128],gray:[128,128,128],silver:[192,192,192]};
dojo.graphics.color.blend=function(a,b,_34f){
if(typeof a=="string"){
return dojo.graphics.color.blendHex(a,b,_34f);
}
if(!_34f){
_34f=0;
}else{
if(_34f>1){
_34f=1;
}else{
if(_34f<-1){
_34f=-1;
}
}
}
var c=new Array(3);
for(var i=0;i<3;i++){
var half=Math.abs(a[i]-b[i])/2;
c[i]=Math.floor(Math.min(a[i],b[i])+half+(half*_34f));
}
return c;
};
dojo.graphics.color.blendHex=function(a,b,_355){
return dojo.graphics.color.rgb2hex(dojo.graphics.color.blend(dojo.graphics.color.hex2rgb(a),dojo.graphics.color.hex2rgb(b),_355));
};
dojo.graphics.color.extractRGB=function(_356){
var hex="0123456789abcdef";
_356=_356.toLowerCase();
if(_356.indexOf("rgb")==0){
var _358=_356.match(/rgba*\((\d+), *(\d+), *(\d+)/i);
var ret=_358.splice(1,3);
return ret;
}else{
var _35a=dojo.graphics.color.hex2rgb(_356);
if(_35a){
return _35a;
}else{
return dojo.graphics.color.named[_356]||[255,255,255];
}
}
};
dojo.graphics.color.hex2rgb=function(hex){
var _35c="0123456789ABCDEF";
var rgb=new Array(3);
if(hex.indexOf("#")==0){
hex=hex.substring(1);
}
hex=hex.toUpperCase();
if(hex.replace(new RegExp("["+_35c+"]","g"),"")!=""){
return null;
}
if(hex.length==3){
rgb[0]=hex.charAt(0)+hex.charAt(0);
rgb[1]=hex.charAt(1)+hex.charAt(1);
rgb[2]=hex.charAt(2)+hex.charAt(2);
}else{
rgb[0]=hex.substring(0,2);
rgb[1]=hex.substring(2,4);
rgb[2]=hex.substring(4);
}
for(var i=0;i<rgb.length;i++){
rgb[i]=_35c.indexOf(rgb[i].charAt(0))*16+_35c.indexOf(rgb[i].charAt(1));
}
return rgb;
};
dojo.graphics.color.rgb2hex=function(r,g,b){
if(dojo.lang.isArray(r)){
g=r[1]||0;
b=r[2]||0;
r=r[0]||0;
}
var ret=dojo.lang.map([r,g,b],function(x){
x=new Number(x);
var s=x.toString(16);
while(s.length<2){
s="0"+s;
}
return s;
});
ret.unshift("#");
return ret.join("");
};
dojo.provide("dojo.uri.Uri");
dojo.uri=new function(){
this.joinPath=function(){
var arr=[];
for(var i=0;i<arguments.length;i++){
arr.push(arguments[i]);
}
return arr.join("/").replace(/\/{2,}/g,"/").replace(/((https*|ftps*):)/i,"$1/");
};
this.dojoUri=function(uri){
return new dojo.uri.Uri(dojo.hostenv.getBaseScriptUri(),uri);
};
this.Uri=function(){
var uri=arguments[0];
for(var i=1;i<arguments.length;i++){
if(!arguments[i]){
continue;
}
var _36a=new dojo.uri.Uri(arguments[i].toString());
var _36b=new dojo.uri.Uri(uri.toString());
if(_36a.path==""&&_36a.scheme==null&&_36a.authority==null&&_36a.query==null){
if(_36a.fragment!=null){
_36b.fragment=_36a.fragment;
}
_36a=_36b;
}else{
if(_36a.scheme==null){
_36a.scheme=_36b.scheme;
if(_36a.authority==null){
_36a.authority=_36b.authority;
if(_36a.path.charAt(0)!="/"){
var path=_36b.path.substring(0,_36b.path.lastIndexOf("/")+1)+_36a.path;
var segs=path.split("/");
for(var j=0;j<segs.length;j++){
if(segs[j]=="."){
if(j==segs.length-1){
segs[j]="";
}else{
segs.splice(j,1);
j--;
}
}else{
if(j>0&&!(j==1&&segs[0]=="")&&segs[j]==".."&&segs[j-1]!=".."){
if(j==segs.length-1){
segs.splice(j,1);
segs[j-1]="";
}else{
segs.splice(j-1,2);
j-=2;
}
}
}
}
_36a.path=segs.join("/");
}
}
}
}
uri="";
if(_36a.scheme!=null){
uri+=_36a.scheme+":";
}
if(_36a.authority!=null){
uri+="//"+_36a.authority;
}
uri+=_36a.path;
if(_36a.query!=null){
uri+="?"+_36a.query;
}
if(_36a.fragment!=null){
uri+="#"+_36a.fragment;
}
}
this.uri=uri.toString();
var _36f="^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?$";
var r=this.uri.match(new RegExp(_36f));
this.scheme=r[2]||(r[1]?"":null);
this.authority=r[4]||(r[3]?"":null);
this.path=r[5];
this.query=r[7]||(r[6]?"":null);
this.fragment=r[9]||(r[8]?"":null);
if(this.authority!=null){
_36f="^((([^:]+:)?([^@]+))@)?([^:]*)(:([0-9]+))?$";
r=this.authority.match(new RegExp(_36f));
this.user=r[3]||null;
this.password=r[4]||null;
this.host=r[5];
this.port=r[7]||null;
}
this.toString=function(){
return this.uri;
};
};
};
dojo.provide("dojo.style");
dojo.require("dojo.graphics.color");
dojo.require("dojo.uri.Uri");
dojo.require("dojo.lang.common");
(function(){
var h=dojo.render.html;
var ds=dojo.style;
var db=document["body"]||document["documentElement"];
ds.boxSizing={MARGIN_BOX:"margin-box",BORDER_BOX:"border-box",PADDING_BOX:"padding-box",CONTENT_BOX:"content-box"};
var bs=ds.boxSizing;
ds.getBoxSizing=function(node){
if((h.ie)||(h.opera)){
var cm=document["compatMode"];
if((cm=="BackCompat")||(cm=="QuirksMode")){
return bs.BORDER_BOX;
}else{
return bs.CONTENT_BOX;
}
}else{
if(arguments.length==0){
node=document.documentElement;
}
var _377=ds.getStyle(node,"-moz-box-sizing");
if(!_377){
_377=ds.getStyle(node,"box-sizing");
}
return (_377?_377:bs.CONTENT_BOX);
}
};
ds.isBorderBox=function(node){
return (ds.getBoxSizing(node)==bs.BORDER_BOX);
};
ds.getUnitValue=function(node,_37a,_37b){
var s=ds.getComputedStyle(node,_37a);
if((!s)||((s=="auto")&&(_37b))){
return {value:0,units:"px"};
}
if(dojo.lang.isUndefined(s)){
return ds.getUnitValue.bad;
}
var _37d=s.match(/(\-?[\d.]+)([a-z%]*)/i);
if(!_37d){
return ds.getUnitValue.bad;
}
return {value:Number(_37d[1]),units:_37d[2].toLowerCase()};
};
ds.getUnitValue.bad={value:NaN,units:""};
ds.getPixelValue=function(node,_37f,_380){
var _381=ds.getUnitValue(node,_37f,_380);
if(isNaN(_381.value)){
return 0;
}
if((_381.value)&&(_381.units!="px")){
return NaN;
}
return _381.value;
};
ds.getNumericStyle=function(){
dojo.deprecated("dojo.(style|html).getNumericStyle","in favor of dojo.(style|html).getPixelValue","0.4");
return ds.getPixelValue.apply(this,arguments);
};
ds.setPositivePixelValue=function(node,_383,_384){
if(isNaN(_384)){
return false;
}
node.style[_383]=Math.max(0,_384)+"px";
return true;
};
ds._sumPixelValues=function(node,_386,_387){
var _388=0;
for(var x=0;x<_386.length;x++){
_388+=ds.getPixelValue(node,_386[x],_387);
}
return _388;
};
ds.isPositionAbsolute=function(node){
return (ds.getComputedStyle(node,"position")=="absolute");
};
ds.getBorderExtent=function(node,side){
return (ds.getStyle(node,"border-"+side+"-style")=="none"?0:ds.getPixelValue(node,"border-"+side+"-width"));
};
ds.getMarginWidth=function(node){
return ds._sumPixelValues(node,["margin-left","margin-right"],ds.isPositionAbsolute(node));
};
ds.getBorderWidth=function(node){
return ds.getBorderExtent(node,"left")+ds.getBorderExtent(node,"right");
};
ds.getPaddingWidth=function(node){
return ds._sumPixelValues(node,["padding-left","padding-right"],true);
};
ds.getPadBorderWidth=function(node){
return ds.getPaddingWidth(node)+ds.getBorderWidth(node);
};
ds.getContentBoxWidth=function(node){
node=dojo.byId(node);
return node.offsetWidth-ds.getPadBorderWidth(node);
};
ds.getBorderBoxWidth=function(node){
node=dojo.byId(node);
return node.offsetWidth;
};
ds.getMarginBoxWidth=function(node){
return ds.getInnerWidth(node)+ds.getMarginWidth(node);
};
ds.setContentBoxWidth=function(node,_395){
node=dojo.byId(node);
if(ds.isBorderBox(node)){
_395+=ds.getPadBorderWidth(node);
}
return ds.setPositivePixelValue(node,"width",_395);
};
ds.setMarginBoxWidth=function(node,_397){
node=dojo.byId(node);
if(!ds.isBorderBox(node)){
_397-=ds.getPadBorderWidth(node);
}
_397-=ds.getMarginWidth(node);
return ds.setPositivePixelValue(node,"width",_397);
};
ds.getContentWidth=ds.getContentBoxWidth;
ds.getInnerWidth=ds.getBorderBoxWidth;
ds.getOuterWidth=ds.getMarginBoxWidth;
ds.setContentWidth=ds.setContentBoxWidth;
ds.setOuterWidth=ds.setMarginBoxWidth;
ds.getMarginHeight=function(node){
return ds._sumPixelValues(node,["margin-top","margin-bottom"],ds.isPositionAbsolute(node));
};
ds.getBorderHeight=function(node){
return ds.getBorderExtent(node,"top")+ds.getBorderExtent(node,"bottom");
};
ds.getPaddingHeight=function(node){
return ds._sumPixelValues(node,["padding-top","padding-bottom"],true);
};
ds.getPadBorderHeight=function(node){
return ds.getPaddingHeight(node)+ds.getBorderHeight(node);
};
ds.getContentBoxHeight=function(node){
node=dojo.byId(node);
return node.offsetHeight-ds.getPadBorderHeight(node);
};
ds.getBorderBoxHeight=function(node){
node=dojo.byId(node);
return node.offsetHeight;
};
ds.getMarginBoxHeight=function(node){
return ds.getInnerHeight(node)+ds.getMarginHeight(node);
};
ds.setContentBoxHeight=function(node,_3a0){
node=dojo.byId(node);
if(ds.isBorderBox(node)){
_3a0+=ds.getPadBorderHeight(node);
}
return ds.setPositivePixelValue(node,"height",_3a0);
};
ds.setMarginBoxHeight=function(node,_3a2){
node=dojo.byId(node);
if(!ds.isBorderBox(node)){
_3a2-=ds.getPadBorderHeight(node);
}
_3a2-=ds.getMarginHeight(node);
return ds.setPositivePixelValue(node,"height",_3a2);
};
ds.getContentHeight=ds.getContentBoxHeight;
ds.getInnerHeight=ds.getBorderBoxHeight;
ds.getOuterHeight=ds.getMarginBoxHeight;
ds.setContentHeight=ds.setContentBoxHeight;
ds.setOuterHeight=ds.setMarginBoxHeight;
ds.getAbsolutePosition=ds.abs=function(node,_3a4){
node=dojo.byId(node);
var ret=[];
ret.x=ret.y=0;
var st=dojo.html.getScrollTop();
var sl=dojo.html.getScrollLeft();
if(h.ie){
with(node.getBoundingClientRect()){
ret.x=left-2;
ret.y=top-2;
}
}else{
if(document.getBoxObjectFor){
var bo=document.getBoxObjectFor(node);
ret.x=bo.x-ds.sumAncestorProperties(node,"scrollLeft");
ret.y=bo.y-ds.sumAncestorProperties(node,"scrollTop");
}else{
if(node["offsetParent"]){
var _3a9;
if((h.safari)&&(node.style.getPropertyValue("position")=="absolute")&&(node.parentNode==db)){
_3a9=db;
}else{
_3a9=db.parentNode;
}
if(node.parentNode!=db){
var nd=node;
if(window.opera){
nd=db;
}
ret.x-=ds.sumAncestorProperties(nd,"scrollLeft");
ret.y-=ds.sumAncestorProperties(nd,"scrollTop");
}
do{
var n=node["offsetLeft"];
ret.x+=isNaN(n)?0:n;
var m=node["offsetTop"];
ret.y+=isNaN(m)?0:m;
node=node.offsetParent;
}while((node!=_3a9)&&(node!=null));
}else{
if(node["x"]&&node["y"]){
ret.x+=isNaN(node.x)?0:node.x;
ret.y+=isNaN(node.y)?0:node.y;
}
}
}
}
if(_3a4){
ret.y+=st;
ret.x+=sl;
}
ret[0]=ret.x;
ret[1]=ret.y;
return ret;
};
ds.sumAncestorProperties=function(node,prop){
node=dojo.byId(node);
if(!node){
return 0;
}
var _3af=0;
while(node){
var val=node[prop];
if(val){
_3af+=val-0;
if(node==document.body){
break;
}
}
node=node.parentNode;
}
return _3af;
};
ds.getTotalOffset=function(node,type,_3b3){
return ds.abs(node,_3b3)[(type=="top")?"y":"x"];
};
ds.getAbsoluteX=ds.totalOffsetLeft=function(node,_3b5){
return ds.getTotalOffset(node,"left",_3b5);
};
ds.getAbsoluteY=ds.totalOffsetTop=function(node,_3b7){
return ds.getTotalOffset(node,"top",_3b7);
};
ds.styleSheet=null;
ds.insertCssRule=function(_3b8,_3b9,_3ba){
if(!ds.styleSheet){
if(document.createStyleSheet){
ds.styleSheet=document.createStyleSheet();
}else{
if(document.styleSheets[0]){
ds.styleSheet=document.styleSheets[0];
}else{
return null;
}
}
}
if(arguments.length<3){
if(ds.styleSheet.cssRules){
_3ba=ds.styleSheet.cssRules.length;
}else{
if(ds.styleSheet.rules){
_3ba=ds.styleSheet.rules.length;
}else{
return null;
}
}
}
if(ds.styleSheet.insertRule){
var rule=_3b8+" { "+_3b9+" }";
return ds.styleSheet.insertRule(rule,_3ba);
}else{
if(ds.styleSheet.addRule){
return ds.styleSheet.addRule(_3b8,_3b9,_3ba);
}else{
return null;
}
}
};
ds.removeCssRule=function(_3bc){
if(!ds.styleSheet){
dojo.debug("no stylesheet defined for removing rules");
return false;
}
if(h.ie){
if(!_3bc){
_3bc=ds.styleSheet.rules.length;
ds.styleSheet.removeRule(_3bc);
}
}else{
if(document.styleSheets[0]){
if(!_3bc){
_3bc=ds.styleSheet.cssRules.length;
}
ds.styleSheet.deleteRule(_3bc);
}
}
return true;
};
ds.insertCssFile=function(URI,doc,_3bf){
if(!URI){
return;
}
if(!doc){
doc=document;
}
var _3c0=dojo.hostenv.getText(URI);
_3c0=ds.fixPathsInCssText(_3c0,URI);
if(_3bf){
var _3c1=doc.getElementsByTagName("style");
var _3c2="";
for(var i=0;i<_3c1.length;i++){
_3c2=(_3c1[i].styleSheet&&_3c1[i].styleSheet.cssText)?_3c1[i].styleSheet.cssText:_3c1[i].innerHTML;
if(_3c0==_3c2){
return;
}
}
}
var _3c4=ds.insertCssText(_3c0);
if(_3c4&&djConfig.isDebug){
_3c4.setAttribute("dbgHref",URI);
}
return _3c4;
};
ds.insertCssText=function(_3c5,doc,URI){
if(!_3c5){
return;
}
if(!doc){
doc=document;
}
if(URI){
_3c5=ds.fixPathsInCssText(_3c5,URI);
}
var _3c8=doc.createElement("style");
_3c8.setAttribute("type","text/css");
var head=doc.getElementsByTagName("head")[0];
if(!head){
dojo.debug("No head tag in document, aborting styles");
return;
}else{
head.appendChild(_3c8);
}
if(_3c8.styleSheet){
_3c8.styleSheet.cssText=_3c5;
}else{
var _3ca=doc.createTextNode(_3c5);
_3c8.appendChild(_3ca);
}
return _3c8;
};
ds.fixPathsInCssText=function(_3cb,URI){
if(!_3cb||!URI){
return;
}
var pos=0;
var str="";
var url="";
while(pos!=-1){
pos=0;
url="";
pos=_3cb.indexOf("url(",pos);
if(pos<0){
break;
}
str+=_3cb.slice(0,pos+4);
_3cb=_3cb.substring(pos+4,_3cb.length);
url+=_3cb.match(/^[\t\s\w()\/.\\'"-:#=&?]*\)/)[0];
_3cb=_3cb.substring(url.length-1,_3cb.length);
url=url.replace(/^[\s\t]*(['"]?)([\w()\/.\\'"-:#=&?]*)\1[\s\t]*?\)/,"$2");
if(url.search(/(file|https?|ftps?):\/\//)==-1){
url=(new dojo.uri.Uri(URI,url).toString());
}
str+=url;
}
return str+_3cb;
};
ds.getBackgroundColor=function(node){
node=dojo.byId(node);
var _3d1;
do{
_3d1=ds.getStyle(node,"background-color");
if(_3d1.toLowerCase()=="rgba(0, 0, 0, 0)"){
_3d1="transparent";
}
if(node==document.getElementsByTagName("body")[0]){
node=null;
break;
}
node=node.parentNode;
}while(node&&dojo.lang.inArray(_3d1,["transparent",""]));
if(_3d1=="transparent"){
_3d1=[255,255,255,0];
}else{
_3d1=dojo.graphics.color.extractRGB(_3d1);
}
return _3d1;
};
ds.getComputedStyle=function(node,_3d3,_3d4){
node=dojo.byId(node);
var _3d3=ds.toSelectorCase(_3d3);
var _3d5=ds.toCamelCase(_3d3);
if(!node||!node.style){
return _3d4;
}else{
if(document.defaultView){
try{
var cs=document.defaultView.getComputedStyle(node,"");
if(cs){
return cs.getPropertyValue(_3d3);
}
}
catch(e){
if(node.style.getPropertyValue){
return node.style.getPropertyValue(_3d3);
}else{
return _3d4;
}
}
}else{
if(node.currentStyle){
return node.currentStyle[_3d5];
}
}
}
if(node.style.getPropertyValue){
return node.style.getPropertyValue(_3d3);
}else{
return _3d4;
}
};
ds.getStyleProperty=function(node,_3d8){
node=dojo.byId(node);
return (node&&node.style?node.style[ds.toCamelCase(_3d8)]:undefined);
};
ds.getStyle=function(node,_3da){
var _3db=ds.getStyleProperty(node,_3da);
return (_3db?_3db:ds.getComputedStyle(node,_3da));
};
ds.setStyle=function(node,_3dd,_3de){
node=dojo.byId(node);
if(node&&node.style){
var _3df=ds.toCamelCase(_3dd);
node.style[_3df]=_3de;
}
};
ds.toCamelCase=function(_3e0){
var arr=_3e0.split("-"),cc=arr[0];
for(var i=1;i<arr.length;i++){
cc+=arr[i].charAt(0).toUpperCase()+arr[i].substring(1);
}
return cc;
};
ds.toSelectorCase=function(_3e3){
return _3e3.replace(/([A-Z])/g,"-$1").toLowerCase();
};
ds.setOpacity=function setOpacity(node,_3e5,_3e6){
node=dojo.byId(node);
if(!_3e6){
if(_3e5>=1){
if(h.ie){
ds.clearOpacity(node);
return;
}else{
_3e5=0.999999;
}
}else{
if(_3e5<0){
_3e5=0;
}
}
}
if(h.ie){
if(node.nodeName.toLowerCase()=="tr"){
var tds=node.getElementsByTagName("td");
for(var x=0;x<tds.length;x++){
tds[x].style.filter="Alpha(Opacity="+_3e5*100+")";
}
}
node.style.filter="Alpha(Opacity="+_3e5*100+")";
}else{
if(h.moz){
node.style.opacity=_3e5;
node.style.MozOpacity=_3e5;
}else{
if(h.safari){
node.style.opacity=_3e5;
node.style.KhtmlOpacity=_3e5;
}else{
node.style.opacity=_3e5;
}
}
}
};
ds.getOpacity=function getOpacity(node){
node=dojo.byId(node);
if(h.ie){
var opac=(node.filters&&node.filters.alpha&&typeof node.filters.alpha.opacity=="number"?node.filters.alpha.opacity:100)/100;
}else{
var opac=node.style.opacity||node.style.MozOpacity||node.style.KhtmlOpacity||1;
}
return opac>=0.999999?1:Number(opac);
};
ds.clearOpacity=function clearOpacity(node){
node=dojo.byId(node);
var ns=node.style;
if(h.ie){
try{
if(node.filters&&node.filters.alpha){
ns.filter="";
}
}
catch(e){
}
}else{
if(h.moz){
ns.opacity=1;
ns.MozOpacity=1;
}else{
if(h.safari){
ns.opacity=1;
ns.KhtmlOpacity=1;
}else{
ns.opacity=1;
}
}
}
};
ds.setStyleAttributes=function(node,_3ee){
var _3ef={"opacity":dojo.style.setOpacity,"content-height":dojo.style.setContentHeight,"content-width":dojo.style.setContentWidth,"outer-height":dojo.style.setOuterHeight,"outer-width":dojo.style.setOuterWidth};
var _3f0=_3ee.replace(/(;)?\s*$/,"").split(";");
for(var i=0;i<_3f0.length;i++){
var _3f2=_3f0[i].split(":");
var name=_3f2[0].replace(/\s*$/,"").replace(/^\s*/,"").toLowerCase();
var _3f4=_3f2[1].replace(/\s*$/,"").replace(/^\s*/,"");
if(dojo.lang.has(_3ef,name)){
_3ef[name](node,_3f4);
}else{
node.style[dojo.style.toCamelCase(name)]=_3f4;
}
}
};
ds._toggle=function(node,_3f6,_3f7){
node=dojo.byId(node);
_3f7(node,!_3f6(node));
return _3f6(node);
};
ds.show=function(node){
node=dojo.byId(node);
if(ds.getStyleProperty(node,"display")=="none"){
ds.setStyle(node,"display",(node.dojoDisplayCache||""));
node.dojoDisplayCache=undefined;
}
};
ds.hide=function(node){
node=dojo.byId(node);
if(typeof node["dojoDisplayCache"]=="undefined"){
var d=ds.getStyleProperty(node,"display");
if(d!="none"){
node.dojoDisplayCache=d;
}
}
ds.setStyle(node,"display","none");
};
ds.setShowing=function(node,_3fc){
ds[(_3fc?"show":"hide")](node);
};
ds.isShowing=function(node){
return (ds.getStyleProperty(node,"display")!="none");
};
ds.toggleShowing=function(node){
return ds._toggle(node,ds.isShowing,ds.setShowing);
};
ds.displayMap={tr:"",td:"",th:"",img:"inline",span:"inline",input:"inline",button:"inline"};
ds.suggestDisplayByTagName=function(node){
node=dojo.byId(node);
if(node&&node.tagName){
var tag=node.tagName.toLowerCase();
return (tag in ds.displayMap?ds.displayMap[tag]:"block");
}
};
ds.setDisplay=function(node,_402){
ds.setStyle(node,"display",(dojo.lang.isString(_402)?_402:(_402?ds.suggestDisplayByTagName(node):"none")));
};
ds.isDisplayed=function(node){
return (ds.getComputedStyle(node,"display")!="none");
};
ds.toggleDisplay=function(node){
return ds._toggle(node,ds.isDisplayed,ds.setDisplay);
};
ds.setVisibility=function(node,_406){
ds.setStyle(node,"visibility",(dojo.lang.isString(_406)?_406:(_406?"visible":"hidden")));
};
ds.isVisible=function(node){
return (ds.getComputedStyle(node,"visibility")!="hidden");
};
ds.toggleVisibility=function(node){
return ds._toggle(node,ds.isVisible,ds.setVisibility);
};
ds.toCoordinateArray=function(_409,_40a){
if(dojo.lang.isArray(_409)){
while(_409.length<4){
_409.push(0);
}
while(_409.length>4){
_409.pop();
}
var ret=_409;
}else{
var node=dojo.byId(_409);
var pos=ds.getAbsolutePosition(node,_40a);
var ret=[pos.x,pos.y,ds.getBorderBoxWidth(node),ds.getBorderBoxHeight(node)];
}
ret.x=ret[0];
ret.y=ret[1];
ret.w=ret[2];
ret.h=ret[3];
return ret;
};
})();
dojo.provide("dojo.html");
dojo.require("dojo.lang.func");
dojo.require("dojo.dom");
dojo.require("dojo.style");
dojo.require("dojo.string");
dojo.lang.mixin(dojo.html,dojo.dom);
dojo.lang.mixin(dojo.html,dojo.style);
dojo.html.clearSelection=function(){
try{
if(window["getSelection"]){
if(dojo.render.html.safari){
window.getSelection().collapse();
}else{
window.getSelection().removeAllRanges();
}
}else{
if(document.selection){
if(document.selection.empty){
document.selection.empty();
}else{
if(document.selection.clear){
document.selection.clear();
}
}
}
}
return true;
}
catch(e){
dojo.debug(e);
return false;
}
};
dojo.html.disableSelection=function(_40e){
_40e=dojo.byId(_40e)||document.body;
var h=dojo.render.html;
if(h.mozilla){
_40e.style.MozUserSelect="none";
}else{
if(h.safari){
_40e.style.KhtmlUserSelect="none";
}else{
if(h.ie){
_40e.unselectable="on";
}else{
return false;
}
}
}
return true;
};
dojo.html.enableSelection=function(_410){
_410=dojo.byId(_410)||document.body;
var h=dojo.render.html;
if(h.mozilla){
_410.style.MozUserSelect="";
}else{
if(h.safari){
_410.style.KhtmlUserSelect="";
}else{
if(h.ie){
_410.unselectable="off";
}else{
return false;
}
}
}
return true;
};
dojo.html.selectElement=function(_412){
_412=dojo.byId(_412);
if(document.selection&&document.body.createTextRange){
var _413=document.body.createTextRange();
_413.moveToElementText(_412);
_413.select();
}else{
if(window["getSelection"]){
var _414=window.getSelection();
if(_414["selectAllChildren"]){
_414.selectAllChildren(_412);
}
}
}
};
dojo.html.selectInputText=function(_415){
_415=dojo.byId(_415);
if(document.selection&&document.body.createTextRange){
var _416=_415.createTextRange();
_416.moveStart("character",0);
_416.moveEnd("character",_415.value.length);
_416.select();
}else{
if(window["getSelection"]){
var _417=window.getSelection();
_415.setSelectionRange(0,_415.value.length);
}
}
_415.focus();
};
dojo.html.isSelectionCollapsed=function(){
if(document["selection"]){
return document.selection.createRange().text=="";
}else{
if(window["getSelection"]){
var _418=window.getSelection();
if(dojo.lang.isString(_418)){
return _418=="";
}else{
return _418.isCollapsed;
}
}
}
};
dojo.html.getEventTarget=function(evt){
if(!evt){
evt=window.event||{};
}
var t=(evt.srcElement?evt.srcElement:(evt.target?evt.target:null));
while((t)&&(t.nodeType!=1)){
t=t.parentNode;
}
return t;
};
dojo.html.getDocumentWidth=function(){
dojo.deprecated("dojo.html.getDocument*","replaced by dojo.html.getViewport*","0.4");
return dojo.html.getViewportWidth();
};
dojo.html.getDocumentHeight=function(){
dojo.deprecated("dojo.html.getDocument*","replaced by dojo.html.getViewport*","0.4");
return dojo.html.getViewportHeight();
};
dojo.html.getDocumentSize=function(){
dojo.deprecated("dojo.html.getDocument*","replaced of dojo.html.getViewport*","0.4");
return dojo.html.getViewportSize();
};
dojo.html.getViewportWidth=function(){
var w=0;
if(window.innerWidth){
w=window.innerWidth;
}
if(dojo.exists(document,"documentElement.clientWidth")){
var w2=document.documentElement.clientWidth;
if(!w||w2&&w2<w){
w=w2;
}
return w;
}
if(document.body){
return document.body.clientWidth;
}
return 0;
};
dojo.html.getViewportHeight=function(){
if(window.innerHeight){
return window.innerHeight;
}
if(dojo.exists(document,"documentElement.clientHeight")){
return document.documentElement.clientHeight;
}
if(document.body){
return document.body.clientHeight;
}
return 0;
};
dojo.html.getViewportSize=function(){
var ret=[dojo.html.getViewportWidth(),dojo.html.getViewportHeight()];
ret.w=ret[0];
ret.h=ret[1];
return ret;
};
dojo.html.getScrollTop=function(){
return window.pageYOffset||document.documentElement.scrollTop||document.body.scrollTop||0;
};
dojo.html.getScrollLeft=function(){
return window.pageXOffset||document.documentElement.scrollLeft||document.body.scrollLeft||0;
};
dojo.html.getScrollOffset=function(){
var off=[dojo.html.getScrollLeft(),dojo.html.getScrollTop()];
off.x=off[0];
off.y=off[1];
return off;
};
dojo.html.getParentOfType=function(node,type){
dojo.deprecated("dojo.html.getParentOfType","replaced by dojo.html.getParentByType*","0.4");
return dojo.html.getParentByType(node,type);
};
dojo.html.getParentByType=function(node,type){
var _423=dojo.byId(node);
type=type.toLowerCase();
while((_423)&&(_423.nodeName.toLowerCase()!=type)){
if(_423==(document["body"]||document["documentElement"])){
return null;
}
_423=_423.parentNode;
}
return _423;
};
dojo.html.getAttribute=function(node,attr){
node=dojo.byId(node);
if((!node)||(!node.getAttribute)){
return null;
}
var ta=typeof attr=="string"?attr:new String(attr);
var v=node.getAttribute(ta.toUpperCase());
if((v)&&(typeof v=="string")&&(v!="")){
return v;
}
if(v&&v.value){
return v.value;
}
if((node.getAttributeNode)&&(node.getAttributeNode(ta))){
return (node.getAttributeNode(ta)).value;
}else{
if(node.getAttribute(ta)){
return node.getAttribute(ta);
}else{
if(node.getAttribute(ta.toLowerCase())){
return node.getAttribute(ta.toLowerCase());
}
}
}
return null;
};
dojo.html.hasAttribute=function(node,attr){
node=dojo.byId(node);
return dojo.html.getAttribute(node,attr)?true:false;
};
dojo.html.getClass=function(node){
node=dojo.byId(node);
if(!node){
return "";
}
var cs="";
if(node.className){
cs=node.className;
}else{
if(dojo.html.hasAttribute(node,"class")){
cs=dojo.html.getAttribute(node,"class");
}
}
return dojo.string.trim(cs);
};
dojo.html.getClasses=function(node){
var c=dojo.html.getClass(node);
return (c=="")?[]:c.split(/\s+/g);
};
dojo.html.hasClass=function(node,_42f){
return dojo.lang.inArray(dojo.html.getClasses(node),_42f);
};
dojo.html.prependClass=function(node,_431){
_431+=" "+dojo.html.getClass(node);
return dojo.html.setClass(node,_431);
};
dojo.html.addClass=function(node,_433){
if(dojo.html.hasClass(node,_433)){
return false;
}
_433=dojo.string.trim(dojo.html.getClass(node)+" "+_433);
return dojo.html.setClass(node,_433);
};
dojo.html.setClass=function(node,_435){
node=dojo.byId(node);
var cs=new String(_435);
try{
if(typeof node.className=="string"){
node.className=cs;
}else{
if(node.setAttribute){
node.setAttribute("class",_435);
node.className=cs;
}else{
return false;
}
}
}
catch(e){
dojo.debug("dojo.html.setClass() failed",e);
}
return true;
};
dojo.html.removeClass=function(node,_438,_439){
var _438=dojo.string.trim(new String(_438));
try{
var cs=dojo.html.getClasses(node);
var nca=[];
if(_439){
for(var i=0;i<cs.length;i++){
if(cs[i].indexOf(_438)==-1){
nca.push(cs[i]);
}
}
}else{
for(var i=0;i<cs.length;i++){
if(cs[i]!=_438){
nca.push(cs[i]);
}
}
}
dojo.html.setClass(node,nca.join(" "));
}
catch(e){
dojo.debug("dojo.html.removeClass() failed",e);
}
return true;
};
dojo.html.replaceClass=function(node,_43e,_43f){
dojo.html.removeClass(node,_43f);
dojo.html.addClass(node,_43e);
};
dojo.html.classMatchType={ContainsAll:0,ContainsAny:1,IsOnly:2};
dojo.html.getElementsByClass=function(_440,_441,_442,_443,_444){
_441=dojo.byId(_441)||document;
var _445=_440.split(/\s+/g);
var _446=[];
if(_443!=1&&_443!=2){
_443=0;
}
var _447=new RegExp("(\\s|^)(("+_445.join(")|(")+"))(\\s|$)");
var _448=[];
if(!_444&&document.evaluate){
var _449="//"+(_442||"*")+"[contains(";
if(_443!=dojo.html.classMatchType.ContainsAny){
_449+="concat(' ',@class,' '), ' "+_445.join(" ') and contains(concat(' ',@class,' '), ' ")+" ')]";
}else{
_449+="concat(' ',@class,' '), ' "+_445.join(" ')) or contains(concat(' ',@class,' '), ' ")+" ')]";
}
var _44a=document.evaluate(_449,_441,null,XPathResult.ANY_TYPE,null);
var _44b=_44a.iterateNext();
while(_44b){
try{
_448.push(_44b);
_44b=_44a.iterateNext();
}
catch(e){
break;
}
}
return _448;
}else{
if(!_442){
_442="*";
}
_448=_441.getElementsByTagName(_442);
var node,i=0;
outer:
while(node=_448[i++]){
var _44d=dojo.html.getClasses(node);
if(_44d.length==0){
continue outer;
}
var _44e=0;
for(var j=0;j<_44d.length;j++){
if(_447.test(_44d[j])){
if(_443==dojo.html.classMatchType.ContainsAny){
_446.push(node);
continue outer;
}else{
_44e++;
}
}else{
if(_443==dojo.html.classMatchType.IsOnly){
continue outer;
}
}
}
if(_44e==_445.length){
if((_443==dojo.html.classMatchType.IsOnly)&&(_44e==_44d.length)){
_446.push(node);
}else{
if(_443==dojo.html.classMatchType.ContainsAll){
_446.push(node);
}
}
}
}
return _446;
}
};
dojo.html.getElementsByClassName=dojo.html.getElementsByClass;
dojo.html.getCursorPosition=function(e){
e=e||window.event;
var _451={x:0,y:0};
if(e.pageX||e.pageY){
_451.x=e.pageX;
_451.y=e.pageY;
}else{
var de=document.documentElement;
var db=document.body;
_451.x=e.clientX+((de||db)["scrollLeft"])-((de||db)["clientLeft"]);
_451.y=e.clientY+((de||db)["scrollTop"])-((de||db)["clientTop"]);
}
return _451;
};
dojo.html.overElement=function(_454,e){
_454=dojo.byId(_454);
var _456=dojo.html.getCursorPosition(e);
with(dojo.html){
var top=getAbsoluteY(_454,true);
var _458=top+getInnerHeight(_454);
var left=getAbsoluteX(_454,true);
var _45a=left+getInnerWidth(_454);
}
return (_456.x>=left&&_456.x<=_45a&&_456.y>=top&&_456.y<=_458);
};
dojo.html.setActiveStyleSheet=function(_45b){
var i=0,a,els=document.getElementsByTagName("link");
while(a=els[i++]){
if(a.getAttribute("rel").indexOf("style")!=-1&&a.getAttribute("title")){
a.disabled=true;
if(a.getAttribute("title")==_45b){
a.disabled=false;
}
}
}
};
dojo.html.getActiveStyleSheet=function(){
var i=0,a,els=document.getElementsByTagName("link");
while(a=els[i++]){
if(a.getAttribute("rel").indexOf("style")!=-1&&a.getAttribute("title")&&!a.disabled){
return a.getAttribute("title");
}
}
return null;
};
dojo.html.getPreferredStyleSheet=function(){
var i=0,a,els=document.getElementsByTagName("link");
while(a=els[i++]){
if(a.getAttribute("rel").indexOf("style")!=-1&&a.getAttribute("rel").indexOf("alt")==-1&&a.getAttribute("title")){
return a.getAttribute("title");
}
}
return null;
};
dojo.html.body=function(){
return document.body||document.getElementsByTagName("body")[0];
};
dojo.html.isTag=function(node){
node=dojo.byId(node);
if(node&&node.tagName){
var arr=dojo.lang.map(dojo.lang.toArray(arguments,1),function(a){
return String(a).toLowerCase();
});
return arr[dojo.lang.find(node.tagName.toLowerCase(),arr)]||"";
}
return "";
};
dojo.html.copyStyle=function(_462,_463){
if(dojo.lang.isUndefined(_463.style.cssText)){
_462.setAttribute("style",_463.getAttribute("style"));
}else{
_462.style.cssText=_463.style.cssText;
}
dojo.html.addClass(_462,dojo.html.getClass(_463));
};
dojo.html._callExtrasDeprecated=function(_464,args){
var _466="dojo.html.extras";
dojo.deprecated("dojo.html."+_464,"moved to "+_466,"0.4");
dojo["require"](_466);
return dojo.html[_464].apply(dojo.html,args);
};
dojo.html.createNodesFromText=function(){
return dojo.html._callExtrasDeprecated("createNodesFromText",arguments);
};
dojo.html.gravity=function(){
return dojo.html._callExtrasDeprecated("gravity",arguments);
};
dojo.html.placeOnScreen=function(){
return dojo.html._callExtrasDeprecated("placeOnScreen",arguments);
};
dojo.html.placeOnScreenPoint=function(){
return dojo.html._callExtrasDeprecated("placeOnScreenPoint",arguments);
};
dojo.html.renderedTextContent=function(){
return dojo.html._callExtrasDeprecated("renderedTextContent",arguments);
};
dojo.html.BackgroundIframe=function(){
return dojo.html._callExtrasDeprecated("BackgroundIframe",arguments);
};
dojo.provide("dojo.lfx.html");
dojo.require("dojo.lfx.Animation");
dojo.require("dojo.html");
dojo.lfx.html._byId=function(_467){
if(!_467){
return [];
}
if(dojo.lang.isArray(_467)){
if(!_467.alreadyChecked){
var n=[];
dojo.lang.forEach(_467,function(node){
n.push(dojo.byId(node));
});
n.alreadyChecked=true;
return n;
}else{
return _467;
}
}else{
var n=[];
n.push(dojo.byId(_467));
n.alreadyChecked=true;
return n;
}
};
dojo.lfx.html.propertyAnimation=function(_46a,_46b,_46c,_46d){
_46a=dojo.lfx.html._byId(_46a);
if(_46a.length==1){
dojo.lang.forEach(_46b,function(prop){
if(typeof prop["start"]=="undefined"){
if(prop.property!="opacity"){
prop.start=parseInt(dojo.style.getComputedStyle(_46a[0],prop.property));
}else{
prop.start=dojo.style.getOpacity(_46a[0]);
}
}
});
}
var _46f=function(_470){
var _471=new Array(_470.length);
for(var i=0;i<_470.length;i++){
_471[i]=Math.round(_470[i]);
}
return _471;
};
var _473=function(n,_475){
n=dojo.byId(n);
if(!n||!n.style){
return;
}
for(var s in _475){
if(s=="opacity"){
dojo.style.setOpacity(n,_475[s]);
}else{
n.style[s]=_475[s];
}
}
};
var _477=function(_478){
this._properties=_478;
this.diffs=new Array(_478.length);
dojo.lang.forEach(_478,function(prop,i){
if(dojo.lang.isArray(prop.start)){
this.diffs[i]=null;
}else{
if(prop.start instanceof dojo.graphics.color.Color){
prop.startRgb=prop.start.toRgb();
prop.endRgb=prop.end.toRgb();
}else{
this.diffs[i]=prop.end-prop.start;
}
}
},this);
this.getValue=function(n){
var ret={};
dojo.lang.forEach(this._properties,function(prop,i){
var _47f=null;
if(dojo.lang.isArray(prop.start)){
}else{
if(prop.start instanceof dojo.graphics.color.Color){
_47f=(prop.units||"rgb")+"(";
for(var j=0;j<prop.startRgb.length;j++){
_47f+=Math.round(((prop.endRgb[j]-prop.startRgb[j])*n)+prop.startRgb[j])+(j<prop.startRgb.length-1?",":"");
}
_47f+=")";
}else{
_47f=((this.diffs[i])*n)+prop.start+(prop.property!="opacity"?prop.units||"px":"");
}
}
ret[dojo.style.toCamelCase(prop.property)]=_47f;
},this);
return ret;
};
};
var anim=new dojo.lfx.Animation({onAnimate:function(_482){
dojo.lang.forEach(_46a,function(node){
_473(node,_482);
});
}},_46c,new _477(_46b),_46d);
return anim;
};
dojo.lfx.html._makeFadeable=function(_484){
var _485=function(node){
if(dojo.render.html.ie){
if((node.style.zoom.length==0)&&(dojo.style.getStyle(node,"zoom")=="normal")){
node.style.zoom="1";
}
if((node.style.width.length==0)&&(dojo.style.getStyle(node,"width")=="auto")){
node.style.width="auto";
}
}
};
if(dojo.lang.isArrayLike(_484)){
dojo.lang.forEach(_484,_485);
}else{
_485(_484);
}
};
dojo.lfx.html.fadeIn=function(_487,_488,_489,_48a){
_487=dojo.lfx.html._byId(_487);
dojo.lfx.html._makeFadeable(_487);
var anim=dojo.lfx.propertyAnimation(_487,[{property:"opacity",start:dojo.style.getOpacity(_487[0]),end:1}],_488,_489);
if(_48a){
var _48c=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_48c();
_48a(_487,anim);
};
}
return anim;
};
dojo.lfx.html.fadeOut=function(_48d,_48e,_48f,_490){
_48d=dojo.lfx.html._byId(_48d);
dojo.lfx.html._makeFadeable(_48d);
var anim=dojo.lfx.propertyAnimation(_48d,[{property:"opacity",start:dojo.style.getOpacity(_48d[0]),end:0}],_48e,_48f);
if(_490){
var _492=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_492();
_490(_48d,anim);
};
}
return anim;
};
dojo.lfx.html.fadeShow=function(_493,_494,_495,_496){
var anim=dojo.lfx.html.fadeIn(_493,_494,_495,_496);
var _498=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_498();
if(dojo.lang.isArrayLike(_493)){
dojo.lang.forEach(_493,dojo.style.show);
}else{
dojo.style.show(_493);
}
};
return anim;
};
dojo.lfx.html.fadeHide=function(_499,_49a,_49b,_49c){
var anim=dojo.lfx.html.fadeOut(_499,_49a,_49b,function(){
if(dojo.lang.isArrayLike(_499)){
dojo.lang.forEach(_499,dojo.style.hide);
}else{
dojo.style.hide(_499);
}
if(_49c){
_49c(_499,anim);
}
});
return anim;
};
dojo.lfx.html.wipeIn=function(_49e,_49f,_4a0,_4a1){
_49e=dojo.lfx.html._byId(_49e);
var _4a2=[];
dojo.lang.forEach(_49e,function(node){
var _4a4=dojo.style.getStyle(node,"overflow");
if(_4a4=="visible"){
node.style.overflow="hidden";
}
node.style.height="0px";
dojo.style.show(node);
var anim=dojo.lfx.propertyAnimation(node,[{property:"height",start:0,end:node.scrollHeight}],_49f,_4a0);
var _4a6=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4a6();
node.style.overflow=_4a4;
node.style.height="auto";
if(_4a1){
_4a1(node,anim);
}
};
_4a2.push(anim);
});
if(_49e.length>1){
return dojo.lfx.combine(_4a2);
}else{
return _4a2[0];
}
};
dojo.lfx.html.wipeOut=function(_4a7,_4a8,_4a9,_4aa){
_4a7=dojo.lfx.html._byId(_4a7);
var _4ab=[];
dojo.lang.forEach(_4a7,function(node){
var _4ad=dojo.style.getStyle(node,"overflow");
if(_4ad=="visible"){
node.style.overflow="hidden";
}
dojo.style.show(node);
var anim=dojo.lfx.propertyAnimation(node,[{property:"height",start:dojo.style.getContentBoxHeight(node),end:0}],_4a8,_4a9);
var _4af=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4af();
dojo.style.hide(node);
node.style.overflow=_4ad;
if(_4aa){
_4aa(node,anim);
}
};
_4ab.push(anim);
});
if(_4a7.length>1){
return dojo.lfx.combine(_4ab);
}else{
return _4ab[0];
}
};
dojo.lfx.html.slideTo=function(_4b0,_4b1,_4b2,_4b3,_4b4){
_4b0=dojo.lfx.html._byId(_4b0);
var _4b5=[];
dojo.lang.forEach(_4b0,function(node){
var top=null;
var left=null;
var init=(function(){
var _4ba=node;
return function(){
top=_4ba.offsetTop;
left=_4ba.offsetLeft;
if(!dojo.style.isPositionAbsolute(_4ba)){
var ret=dojo.style.abs(_4ba,true);
dojo.style.setStyleAttributes(_4ba,"position:absolute;top:"+ret.y+"px;left:"+ret.x+"px;");
top=ret.y;
left=ret.x;
}
};
})();
init();
var anim=dojo.lfx.propertyAnimation(node,[{property:"top",start:top,end:_4b1[0]},{property:"left",start:left,end:_4b1[1]}],_4b2,_4b3);
var _4bd=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_4bd();
init();
};
if(_4b4){
var _4be=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4be();
_4b4(_4b0,anim);
};
}
_4b5.push(anim);
});
if(_4b0.length>1){
return dojo.lfx.combine(_4b5);
}else{
return _4b5[0];
}
};
dojo.lfx.html.slideBy=function(_4bf,_4c0,_4c1,_4c2,_4c3){
_4bf=dojo.lfx.html._byId(_4bf);
var _4c4=[];
dojo.lang.forEach(_4bf,function(node){
var top=null;
var left=null;
var init=(function(){
var _4c9=node;
return function(){
top=node.offsetTop;
left=node.offsetLeft;
if(!dojo.style.isPositionAbsolute(_4c9)){
var ret=dojo.style.abs(_4c9);
dojo.style.setStyleAttributes(_4c9,"position:absolute;top:"+ret.y+"px;left:"+ret.x+"px;");
top=ret.y;
left=ret.x;
}
};
})();
init();
var anim=dojo.lfx.propertyAnimation(node,[{property:"top",start:top,end:top+_4c0[0]},{property:"left",start:left,end:left+_4c0[1]}],_4c1,_4c2);
var _4cc=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_4cc();
init();
};
if(_4c3){
var _4cd=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4cd();
_4c3(_4bf,anim);
};
}
_4c4.push(anim);
});
if(_4bf.length>1){
return dojo.lfx.combine(_4c4);
}else{
return _4c4[0];
}
};
dojo.lfx.html.explode=function(_4ce,_4cf,_4d0,_4d1,_4d2){
_4ce=dojo.byId(_4ce);
_4cf=dojo.byId(_4cf);
var _4d3=dojo.style.toCoordinateArray(_4ce,true);
var _4d4=document.createElement("div");
dojo.html.copyStyle(_4d4,_4cf);
with(_4d4.style){
position="absolute";
display="none";
}
document.body.appendChild(_4d4);
with(_4cf.style){
visibility="hidden";
display="block";
}
var _4d5=dojo.style.toCoordinateArray(_4cf,true);
with(_4cf.style){
display="none";
visibility="visible";
}
var anim=new dojo.lfx.propertyAnimation(_4d4,[{property:"height",start:_4d3[3],end:_4d5[3]},{property:"width",start:_4d3[2],end:_4d5[2]},{property:"top",start:_4d3[1],end:_4d5[1]},{property:"left",start:_4d3[0],end:_4d5[0]},{property:"opacity",start:0.3,end:1}],_4d0,_4d1);
anim.beforeBegin=function(){
dojo.style.setDisplay(_4d4,"block");
};
anim.onEnd=function(){
dojo.style.setDisplay(_4cf,"block");
_4d4.parentNode.removeChild(_4d4);
};
if(_4d2){
var _4d7=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4d7();
_4d2(_4cf,anim);
};
}
return anim;
};
dojo.lfx.html.implode=function(_4d8,end,_4da,_4db,_4dc){
_4d8=dojo.byId(_4d8);
end=dojo.byId(end);
var _4dd=dojo.style.toCoordinateArray(_4d8,true);
var _4de=dojo.style.toCoordinateArray(end,true);
var _4df=document.createElement("div");
dojo.html.copyStyle(_4df,_4d8);
dojo.style.setOpacity(_4df,0.3);
with(_4df.style){
position="absolute";
display="none";
}
document.body.appendChild(_4df);
var anim=new dojo.lfx.propertyAnimation(_4df,[{property:"height",start:_4dd[3],end:_4de[3]},{property:"width",start:_4dd[2],end:_4de[2]},{property:"top",start:_4dd[1],end:_4de[1]},{property:"left",start:_4dd[0],end:_4de[0]},{property:"opacity",start:1,end:0.3}],_4da,_4db);
anim.beforeBegin=function(){
dojo.style.hide(_4d8);
dojo.style.show(_4df);
};
anim.onEnd=function(){
_4df.parentNode.removeChild(_4df);
};
if(_4dc){
var _4e1=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4e1();
_4dc(_4d8,anim);
};
}
return anim;
};
dojo.lfx.html.highlight=function(_4e2,_4e3,_4e4,_4e5,_4e6){
_4e2=dojo.lfx.html._byId(_4e2);
var _4e7=[];
dojo.lang.forEach(_4e2,function(node){
var _4e9=dojo.style.getBackgroundColor(node);
var bg=dojo.style.getStyle(node,"background-color").toLowerCase();
var _4eb=dojo.style.getStyle(node,"background-image");
var _4ec=(bg=="transparent"||bg=="rgba(0, 0, 0, 0)");
while(_4e9.length>3){
_4e9.pop();
}
var rgb=new dojo.graphics.color.Color(_4e3);
var _4ee=new dojo.graphics.color.Color(_4e9);
var anim=dojo.lfx.propertyAnimation(node,[{property:"background-color",start:rgb,end:_4ee}],_4e4,_4e5);
var _4f0=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_4f0();
if(_4eb){
node.style.backgroundImage="none";
}
node.style.backgroundColor="rgb("+rgb.toRgb().join(",")+")";
};
var _4f1=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4f1();
if(_4eb){
node.style.backgroundImage=_4eb;
}
if(_4ec){
node.style.backgroundColor="transparent";
}
if(_4e6){
_4e6(node,anim);
}
};
_4e7.push(anim);
});
if(_4e2.length>1){
return dojo.lfx.combine(_4e7);
}else{
return _4e7[0];
}
};
dojo.lfx.html.unhighlight=function(_4f2,_4f3,_4f4,_4f5,_4f6){
_4f2=dojo.lfx.html._byId(_4f2);
var _4f7=[];
dojo.lang.forEach(_4f2,function(node){
var _4f9=new dojo.graphics.color.Color(dojo.style.getBackgroundColor(node));
var rgb=new dojo.graphics.color.Color(_4f3);
var _4fb=dojo.style.getStyle(node,"background-image");
var anim=dojo.lfx.propertyAnimation(node,[{property:"background-color",start:_4f9,end:rgb}],_4f4,_4f5);
var _4fd=(anim["beforeBegin"])?dojo.lang.hitch(anim,"beforeBegin"):function(){
};
anim.beforeBegin=function(){
_4fd();
if(_4fb){
node.style.backgroundImage="none";
}
node.style.backgroundColor="rgb("+_4f9.toRgb().join(",")+")";
};
var _4fe=(anim["onEnd"])?dojo.lang.hitch(anim,"onEnd"):function(){
};
anim.onEnd=function(){
_4fe();
if(_4f6){
_4f6(node,anim);
}
};
_4f7.push(anim);
});
if(_4f2.length>1){
return dojo.lfx.combine(_4f7);
}else{
return _4f7[0];
}
};
dojo.lang.mixin(dojo.lfx,dojo.lfx.html);
dojo.kwCompoundRequire({browser:["dojo.lfx.html"],dashboard:["dojo.lfx.html"]});
dojo.provide("dojo.lfx.*");

