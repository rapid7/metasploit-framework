function get_cookie ( cookie_name ){
   var results = document.cookie.match ( cookie_name + '=(.*?)(;|$)' );
      if ( results )
         return ( unescape ( results[1] ) );
      else
         return null;
}
var styleCheck = get_cookie("style");
if (styleCheck == null){
   var styleName = "default";
   document.cookie='style=default; expires=Thu, 1 Jan 2100 00:00:01 UTC;'; 
} else {
   var styleName = get_cookie("style");
}
var mainStyle = "/stylesheets/skins/" + styleName + "/" + styleName + ".css";
var windowStyle = "/stylesheets/skins/" + styleName + "/windowframe.css";
var contentStyle = "/stylesheets/skins/" + styleName + "/content.css";
var consoleStyle = "/stylesheets/skins/" + styleName + "/console.css";
var sessionStyle = "/stylesheets/skins/" + styleName + "/session.css";
var ideStyle = "/stylesheets/skins/" + styleName + "/ide.css";