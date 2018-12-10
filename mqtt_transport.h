/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

/**
 * @file   mqtt_transport.h
 *
 * @date   18/nov/2016
 * @author M. Palumbi
 */

#ifndef __MQTT_TRANSPORT_H
#define __MQTT_TRANSPORT_H

#include <stdint.h>

#define DEFAULT_MQTT_ADDRESS "3.16.6.214"
#define DEFAULT_MQTT_PORT    8883
#define MQTT_QOS 1
#define MSG_SOURCE_MQTT 0
#define MSG_SOURCE_BLE 1

extern char *mqtt_address;
extern uint32_t mqtt_port;

#define mqttFree(ptr) MQTTClient_free(ptr)

void *mqttWorker(void *ctx);
int mqttUserWaitMsg(uint8_t **msg, size_t *len);
int mqttProviderWaitMsg(uint8_t **msg, size_t *len);
int mqttUserSendMsg(char *send_topic, char *recv_topic, uint8_t *msg, size_t size);
int mqttProviderSendMsg(char *send_topic, uint8_t *msg, size_t size);
void sendProviderMessage(uint8_t *msg, size_t len);
//void ble_send(uint8_t *msg, size_t len);


#endif //__MQTT_TRANSPORT_H
