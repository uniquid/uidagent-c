/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

/*
 * @file   mqtt_transport.c
 *
 * @date   18/nov/2016
 * @author M. Palumbi
 */


/**
 * @file mqtt_transport.h
 *
 * worker to manage the MQTT transport
 *
 */

/* include includes */
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include "mqtt_transport.h"
#include "helpers.h"

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"

/**
 * @brief Default cert location
 */
static char certDirectory[PATH_MAX + 1] = "../../../certs";

#define SYNCOBJECT_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0 }
typedef struct {
    pthread_mutex_t mtx;
    pthread_cond_t var;
    unsigned val;
} SyncObject;

char *mqtt_address = DEFAULT_MQTT_ADDRESS;
uint32_t mqtt_port = DEFAULT_MQTT_PORT;
int mqtt_connected = 0;

//mqtt channel staus variables
static AWS_IoT_Client client = {0};
static char *ClientID = NULL;
static char *ServerTopic = NULL;
static char *ClientTopic = NULL;


// receive buffers and synchronization variables
// Provider
static SyncObject prvdRcvSync = SYNCOBJECT_INITIALIZER;
static uint8_t   *prvdRcvMsg = NULL; //provider receive buffer
static size_t     prvdRcvLen = 0;
static int        source = MSG_SOURCE_MQTT; // source of the message
// User
static SyncObject usrRcvSync = SYNCOBJECT_INITIALIZER;
static uint8_t   *usrRcvMsg = NULL; //provider receive buffer
static size_t     usrRcvLen = 0;

void sendProviderMessage(uint8_t *msg, size_t len)
{
        // message for the provider
        pthread_mutex_lock(&(prvdRcvSync.mtx));
        if (prvdRcvSync.val) {
            // previous message still queued.
            // lets remove it
            free(prvdRcvMsg);
        }
        source = MSG_SOURCE_BLE;
        prvdRcvLen = len+1;
        prvdRcvMsg = msg;
        prvdRcvMsg[len] = 0;
        prvdRcvSync.val = 1;
        pthread_cond_signal(&(prvdRcvSync.var));
        pthread_mutex_unlock(&(prvdRcvSync.mtx));
        return ;
}

/**
 * callback called from the MQTT library when a message arrives
 */
static void msgarrvd(AWS_IoT_Client *pClient, char *topicName, uint16_t topicLen, IoT_Publish_Message_Params *message, void *pData)
{
    (void)topicLen;(void)pClient;(void)pData;

    if (0 == memcmp(topicName, ServerTopic, topicLen)) {
        // message for the provider
        pthread_mutex_lock(&(prvdRcvSync.mtx));
        if (prvdRcvSync.val) {
            // previous message still queued.
            // lets remove it
            free(prvdRcvMsg);
        }
        source = MSG_SOURCE_MQTT;
        prvdRcvLen = message->payloadLen+1;
        prvdRcvMsg = malloc(prvdRcvLen);
        memcpy(prvdRcvMsg, message->payload, message->payloadLen);
        prvdRcvMsg[message->payloadLen] = 0;
        prvdRcvSync.val = 1;
        pthread_cond_signal(&(prvdRcvSync.var));
        pthread_mutex_unlock(&(prvdRcvSync.mtx));
        return;
    }
    if (0 == memcmp(topicName, ClientTopic, topicLen)) {
        // message for the user
        pthread_mutex_lock(&(usrRcvSync.mtx));
        if (usrRcvSync.val) {
            // previous message still queued.
            // lets remove it
            free(usrRcvMsg);
        }
        usrRcvLen = message->payloadLen+1;
        usrRcvMsg = malloc(usrRcvLen);
        memcpy(usrRcvMsg, message->payload, message->payloadLen);
        usrRcvMsg[message->payloadLen] = 0;
        usrRcvSync.val = 1;
        pthread_cond_signal(&(usrRcvSync.var));
        pthread_mutex_unlock(&(usrRcvSync.mtx));
        return;
    }

    return;
}

int mqttUserWaitMsg(uint8_t **msg, size_t *len)
{
    pthread_mutex_lock(&(usrRcvSync.mtx));
    while(0 == usrRcvSync.val) // wait for a message
        pthread_cond_wait(&(usrRcvSync.var), &(usrRcvSync.mtx));

    *msg = usrRcvMsg;
    *len = usrRcvLen;
    usrRcvSync.val = 0;
    pthread_mutex_unlock(&(usrRcvSync.mtx));
    return 0;
}

int mqttProviderWaitMsg(uint8_t **msg, size_t *len)
{
    int s;
    pthread_mutex_lock(&(prvdRcvSync.mtx));
    while(0 == prvdRcvSync.val) // wait for a message
        pthread_cond_wait(&(prvdRcvSync.var), &(prvdRcvSync.mtx));

    *msg = prvdRcvMsg;
    *len = prvdRcvLen;
    s = source;
    prvdRcvSync.val = 0;
    pthread_mutex_unlock(&(prvdRcvSync.mtx));
    return s;
}


static void connlost(AWS_IoT_Client *pClient, void *data);

static char rootCA[PATH_MAX + 1] = {0};
static char clientCRT[PATH_MAX + 1] ={0};
static char clientKey[PATH_MAX + 1] ={0};
static char CurrentWD[PATH_MAX + 1] ={0};

static void mqttConnect(int reconnect)
{
    int rc;

    IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;
    IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;

    // Create connection
    if (CLIENT_STATE_INVALID == aws_iot_mqtt_get_client_state(&client)) {

        IOT_INFO("\nAWS IoT SDK Version %d.%d.%d-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

        getcwd(CurrentWD, sizeof(CurrentWD));
        snprintf(rootCA, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_ROOT_CA_FILENAME);

        IOT_DEBUG("rootCA %s", rootCA);
        IOT_DEBUG("clientCRT %s", clientCRT);
        IOT_DEBUG("clientKey %s", clientKey);
        mqttInitParams.enableAutoReconnect = false; // We enable this later below
        mqttInitParams.pHostURL = mqtt_address;//HostAddress;
        mqttInitParams.port = mqtt_port;
        mqttInitParams.pRootCALocation = rootCA;
        mqttInitParams.pDeviceCertLocation = clientCRT;
        mqttInitParams.pDevicePrivateKeyLocation = clientKey;
        mqttInitParams.mqttCommandTimeout_ms = 20000;
        mqttInitParams.tlsHandshakeTimeout_ms = 5000;
        mqttInitParams.isSSLHostnameVerify = true;
        mqttInitParams.disconnectHandler = connlost;
        mqttInitParams.disconnectHandlerData = NULL;

        rc = aws_iot_mqtt_init(&client, &mqttInitParams);
        if(SUCCESS != rc) {
            IOT_ERROR("aws_iot_mqtt_init returned error : %d ", rc);
            exit(-1);
        }
        // disable client certificate authentication and UniquID authentication
        client.networkStack.tlsConnectParams.pUniqIDAuth = NULL;
        client.networkStack.tlsConnectParams.pDeviceCertLocation = "";

    }
    if (aws_iot_mqtt_is_client_connected(&client)) return ;


    // Try to connect
    connectParams.keepAliveIntervalInSec = 60;
    connectParams.isCleanSession = true;
    connectParams.MQTTVersion = MQTT_3_1_1;
    connectParams.pClientID = ClientID;
    connectParams.clientIDLen = (uint16_t) strlen(ClientID);
    connectParams.isWillMsgPresent = false;
    while ((rc = aws_iot_mqtt_connect(&client, &connectParams)) != SUCCESS) {
        DBG_Print("mqtt Failed to connect, return code %d\n", rc);
        sleep(10);
    }
    mqtt_connected = 1;
    DBG_Print("mqtt broker Connected!!\n");

    if(reconnect) {
        while (MQTT_CLIENT_NOT_IDLE_ERROR == (rc = aws_iot_mqtt_resubscribe(&client))) {
            DBG_Print("resubscribe  %d!!!\n", rc);
            usleep(200000);
        };
        return;
    }

    if(NULL != ServerTopic) {
        rc = aws_iot_mqtt_subscribe(&client, ServerTopic, strlen(ServerTopic), MQTT_QOS, msgarrvd, NULL);
        INFO_Print("###################  subscribed %s rc = %d\n", ServerTopic, rc);
    }
    if(NULL != ClientTopic) {
        aws_iot_mqtt_subscribe(&client, ClientTopic, strlen(ClientTopic), MQTT_QOS, msgarrvd, NULL);
    }

    return ;
}


// send buffers and synchronization variables
#define PROVIDER_BUFFER_HAS_DATA 1
#define USER_BUFFER_HAS_DATA 2
#define CONNECTION_LOST 4
static SyncObject sync_msg = SYNCOBJECT_INITIALIZER;
// User
static uint8_t *usrSndMsg = NULL; //user buffer
static size_t usrSndLen = 0;
static char *usrStopic = NULL;
static char *usrRtopic = NULL;
//Provider
static uint8_t *prvdSndMsg = NULL; //provider buffer
static size_t prvdSndLen = 0;
static char *prvdStopic = NULL;

int mqttUserSendMsg(char *send_topic, char *recv_topic, uint8_t *msg, size_t size)
{

    pthread_mutex_lock(&(sync_msg.mtx));
    if (sync_msg.val & USER_BUFFER_HAS_DATA) {
        // previous message not sent. return error.
        //pthread_cond_signal(&(sync_msg.var));
        pthread_mutex_unlock(&(sync_msg.mtx));
        return 1;
    }
    // flush the user receive queue
    pthread_mutex_lock(&(usrRcvSync.mtx));
    if (usrRcvSync.val) {
        // previous message still queued.
        // lets remove it
        free(usrRcvMsg);
        usrRcvSync.val = 0;
    }
    pthread_mutex_unlock(&(usrRcvSync.mtx));
    usrSndMsg = malloc(size);
    usrSndLen = size;
    memcpy(usrSndMsg, msg, size);
    usrStopic = strdup(send_topic);
    usrRtopic = strdup(recv_topic);
    sync_msg.val |= USER_BUFFER_HAS_DATA;
    //pthread_cond_signal(&(sync_msg.var));
    pthread_mutex_unlock(&(sync_msg.mtx));
   return 0;
}

int mqttProviderSendMsg(char *send_topic, uint8_t *msg, size_t size)
{

    pthread_mutex_lock(&(sync_msg.mtx));
    if (sync_msg.val & PROVIDER_BUFFER_HAS_DATA) {
        // previous message not sent. return error.
        //pthread_cond_signal(&(sync_msg.var));
        pthread_mutex_unlock(&(sync_msg.mtx));
        return 1;
    }
    prvdSndMsg = malloc(size);
    prvdSndLen = size;
    memcpy(prvdSndMsg, msg, size);
    prvdStopic = strdup(send_topic);
    sync_msg.val |= PROVIDER_BUFFER_HAS_DATA;
    //pthread_cond_signal(&(sync_msg.var));
    pthread_mutex_unlock(&(sync_msg.mtx));
   return 0;
}

static void connlost(AWS_IoT_Client *pClient, void *context)
{
(void)context;
    if(NULL == pClient) {
        return;
    }
    mqtt_connected = 0;
    DBG_Print("\nmqtt Connection lost\n");
    sleep(10);
    //mqttConnect();
    pthread_mutex_lock(&(sync_msg.mtx));
    sync_msg.val |= CONNECTION_LOST;
    //pthread_cond_signal(&(sync_msg.var));
    pthread_mutex_unlock(&(sync_msg.mtx));
}

/**
 * mqtt worker.
 * @param ctx point to a string used for both ClientID and the main receive topic
 */
void *mqttWorker(void *ctx)
{
    //pthread_t thr;
    ClientID = ctx;
    ServerTopic = ctx;
    mqttConnect(0);
    int res;

    IoT_Publish_Message_Params params_usrSndMsg = {.qos = MQTT_QOS, .isRetained = 0};
    IoT_Publish_Message_Params params_prvdSndMsg = {.qos = MQTT_QOS, .isRetained = 0};


    while(1) {
        pthread_mutex_lock(&(sync_msg.mtx));
        if (sync_msg.val & USER_BUFFER_HAS_DATA) {
            // I have an user message! working on it

            if(NULL != ClientTopic) {
                aws_iot_mqtt_unsubscribe(&client, ClientTopic, strlen(ClientTopic));
                free(ClientTopic);
            }
            ClientTopic = usrRtopic;
            aws_iot_mqtt_subscribe(&client, ClientTopic, strlen(ClientTopic), MQTT_QOS, msgarrvd, NULL);

            params_usrSndMsg.payload = usrSndMsg;
            params_usrSndMsg.payloadLen = usrSndLen;
            while (MQTT_CLIENT_NOT_IDLE_ERROR ==
                    (res = aws_iot_mqtt_publish(&client, usrStopic, strlen(usrStopic), &params_usrSndMsg))) {
                        DBG_Print("publish state = %d\n", res);
                        usleep(200000);
                    }

            free(usrStopic);
            usrStopic = NULL;
            free(usrSndMsg);
            usrSndMsg = NULL;
            usrSndLen = 0;
            sync_msg.val ^= USER_BUFFER_HAS_DATA;
        }
        if (sync_msg.val & PROVIDER_BUFFER_HAS_DATA) {
            // I have a provider message! working on it

            params_prvdSndMsg.payload = prvdSndMsg;
            params_prvdSndMsg.payloadLen = prvdSndLen;
            while (MQTT_CLIENT_NOT_IDLE_ERROR ==
                    (res = aws_iot_mqtt_publish(&client, prvdStopic, strlen(prvdStopic), &params_prvdSndMsg))) {
                        DBG_Print("publish state = %d\n", res);
                        usleep(200000);
                    }

            free(prvdStopic);
            prvdStopic = NULL;
            free(prvdSndMsg);
            prvdSndMsg = NULL;
            prvdSndLen = 0;
            sync_msg.val ^= PROVIDER_BUFFER_HAS_DATA;
        }
        if (sync_msg.val & CONNECTION_LOST) {
            // Connection lost
            mqttConnect(1);

            sync_msg.val ^= CONNECTION_LOST;
        }
        //pthread_cond_wait(&(sync_msg.var), &(sync_msg.mtx));
        pthread_mutex_unlock(&(sync_msg.mtx));
        res = aws_iot_mqtt_yield(&client, 200);
        if (SUCCESS != res) {
            DBG_Print("aws_iot_mqtt_yield() return %d\n", res);
            usleep(300000);
        }
    }
    return 0;
}


