# MQTT

### What is MQTT?

> MQTT stands for MQ Telemetry Transport. It is a publish/subscribe, **extremely simple and lightweight messaging protocol**, designed for constrained devices and low-bandwidth, high-latency or unreliable networks. The design principles are to minimise network bandwidth and device resource requirements whilst also attempting to ensure reliability and some degree of assurance of delivery. These principles also turn out to make the protocol ideal of the emerging “machine-to-machine” (M2M) or “Internet of Things” world of connected devices, and for mobile applications where bandwidth and battery power are at a premium.



### Commands



**Subscribing to all broker statuses:**

```
mosquitto_sub -h TARGET_IP -t '$SYS/#' -v
```



**To publish on the sub\_topic:**

```
mosquitto_pub -h TARGET_IP -t '<sub_topic>' -m 'Test'
```

{% hint style="info" %}
The sub\_topic can be found by using the first command. It might be encoded in base64.
{% endhint %}



**To publish on the pub\_topic:**

```
mosquitto_pub -h TARGET_IP -t '<pub_topic>' -m 'Test'
```

{% hint style="info" %}
The  pub\_topic, is found in the same way the sub\_topic is found. This publisher shows the result of the command you sent while using the mosquitto\_pub command.
{% endhint %}

{% hint style="info" %}
You might have to publish a message encoded in base64, so be careful!

_Example:_

Format: base64({"id": " ", "cmd": " ", "arg": " "})
{% endhint %}



**To listen to the pub\_topic:**

```
mosquitto_sub -h TARGET_IP -t '<pub_topic>' -v
```

