## Contributing modules in [GO](https://golang.org/) can be achieved in a few simple steps:

#### 1. Location
* Select the appropriate [module](https://github.com/rapid7/metasploit-framework/tree/master/modules) path based on the type of module you are trying to contribute
* Be sure to include appropriate module documentation under [here](https://github.com/rapid7/metasploit-framework/tree/master/documentation/modules)
* Test your documentation is correct by executing `info -d`


#### 2. Execution
* Include this line at the top of your module: `//usr/bin/env go run "$0" "$@"; exit "$?"`
* Ensure your file **is** an executable file


#### 3. Setup
* Initialize your module with the module metadata:
>
    import "metasploit/module"
    func main() {
      metadata := &module.Metadata{
        Name: "<module name",
        Description: "<describe>",
        Authors: []string{"<author 1>", "<author 2>"},
        Date: "<date module written",
        Type:"<module type>",
        Privileged:  <true|false>,
        References:  []module.Reference{},
        Options: map[string]module.Option{	
          "<option 1":     {Type: "<type>", Description: "<description>", Required: <true|false>, Default: "<default>"},		
          "<option 2":     {Type: "<type>", Description: "<description>", Required: <true|false>, Default: "<default>"},
      }}

      module.Init(metadata, <the entry method to your module>)
    }

**_Note: Above does not outline the full potential list of metadata options_**

**Currently supported _module types_:**
* remote_exploit
* remote_exploit_cmd_stager
* capture_server
* dos
* single_scanner
* single_host_login_scanner
* multi_scanner

#### 4. Shared Code
* For code that is shared specific to your module create a directory in your module directory:
`shared/src/` metasploit will automatically add these to the GOPATH
* For code that you think could be used across modules, add code [here](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core/modules/external/go/src/metasploit)
* 3rd party libs aren't currently supported but we welcome patches

#### 5. Finalize
* Test your Pull Request
* Create a [Pull Request](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md#pull-requests)
* No coding standard here, be sure to [gofmt](https://blog.golang.org/go-fmt-your-code)
