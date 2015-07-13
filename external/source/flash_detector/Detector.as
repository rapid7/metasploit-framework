/* 
Code to do flash version detection from ActionScript

* How to build:
    1. Use Flex SDK 4.6 / AIRSDK 18 
    2. Build with: mxmlc -o msf.swf Exploit.as
*/

package
{
    import flash.display.Sprite
    import flash.external.ExternalInterface
    import flash.system.Capabilities

    public class Detector extends Sprite
	{
                
        public function Detector()
        {
            var version:String = getVersion()
            ExternalInterface.call("setFlashVersion", version)
        }
        
        private function getVersion():String
        {
            try {
                var version:String = flash.system.Capabilities.version
                version = version.split(/ /)[1]
                version = version.replace(/,/g, ".")
                return version
            } catch (err:Error) {
                return ""
            }
        }
    }
}
