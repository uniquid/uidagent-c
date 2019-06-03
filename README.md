# uidagent-c

## Minimal code implementing an UniquID node. It can be used to add UniquID functionalities to the [AWS IoT C sdk](https://github.com/aws/aws-iot-device-sdk-embedded-C)

It requires:
- libuidcore-c
- libpthread
- AWS IoT mqtt implementation

** check the prerequisites for [uidcore-c here](https://github.com/uniquid/uidcore-c#how-to-build)
### how to integrate in the AWS IoT C sdk
- Clone the AWS-IoT-sdk (this has been tested on tag v3.0.1 and master@c11e34a98be):<br>
``git clone https://github.com/aws/aws-iot-device-sdk-embedded-C.git -b v3.0.1``
- Clone this repository inside the external_libs directory:<br>
``cd aws-iot-device-sdk-embedded-C/external_libs/``<br>
``git clone https://github.com/uniquid/uidagent-c.git``
- Clone the uidcore-c library<br>
``git clone --recurse-submodules https://github.com/uniquid/uidcore-c.git``
- Clone the **mbetls** code:<br>
``rm mbedTLS/README.txt``<br>
``git clone https://github.com/ARMmbed/mbedtls.git mbedTLS -b mbedtls-2.16.1``
- Apply the provided patch, IoT-sdk.patch<br>
``cd ..``<br>
``git apply  external_libs/uidagent-c/IoT-sdk.patch``
- Cd to **subscribe_publish_sample** example and make<br>
``cd samples/linux/subscribe_publish_sample``<br>
``make``

### run the "subscribe_publish_sample"
- copy in the "certs" directory the CA certificates chain to authenticate the aws-mqtt-proxy and the uniquid mqtt broker.<br>
the file must be named **rootCA.crt**:<br>
``cp path-to/caChain.crt ../../../certs/rootCA.crt``
- Copy the configuration file ([here is an example](https://github.com/uniquid/uidagent-c/blob/master/aws_device_cfg.json))<br>
``cp path-to/aws_device_cfg.json aws_device_cfg.json``
- run the sample<br>
``./subscribe_publish_sample``

** configuration can be loaded also from **AWS_AGENT_CONFIG** environment variable:<br>
``export AWS_AGENT_CONFIG=$(cat path-to/aws_device_cfg.json)``
