# Pivoting

### Metasploit & Sock proxy



**Adding Route:**

```
route [add/remove] <subnet><netmask> <session id>
```

_Example:_

```bash
route add 172.17.0.1/32 1
```

####

#### Printing route info:

```bash
route print
```



#### Socks Proxy:

```bash
use auxiliary/server/socks_proxy
```

```bash
run srvhost=127.0.0.1 srvport=9050 version=4a
```



#### Using commands (nmap) via proxy chains:

```bash
proxychains -q nmap <MACHINE_IP>
```



> ## All commands should be executed from background

