# SMB Shares

#### SMB Share List

```
smbclient -L <ip>
```



#### SMB Share List with Username

```
smbclient -U '<username>' -L <ip>
```



#### SMB Share List with Specific Location

```
smbclient -L \\<ip>\Backup\2021
```



#### SMB Share with Interactive Shell

```
smbclient "\\\\<ip>\\Backup" -U '<username>'
```

