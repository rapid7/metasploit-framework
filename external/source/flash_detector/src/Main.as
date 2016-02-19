import flash.external.ExternalInterface
import System.capabilities

class Main 
{
	
	public static function main(swfRoot:MovieClip):Void 
	{
		// entry point
		var app:Main = new Main();
	}
	
	public function Main() 
	{
		var version:String = getVersion()
		ExternalInterface.call("setFlashVersion", version)
	}

	private function getVersion():String
	{
		try {
			var version:String = capabilities.version
			version = version.split(" ")[1]
			version = version.split(",").join(".")
			return version
		} catch (err:Error) {
			return ""
		}
	}
	
}