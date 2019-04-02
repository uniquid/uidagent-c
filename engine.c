/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

/*
 * @file   engine.c
 *
 * @date   11/nov/2018
 * @author M. Palumbi
 */


/**
 * @file engine.h
 *
 * Sample implementation of a Service Provider (machine)
 * 
 */

/* include includes */
#include "UID_message.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdbool.h>

// #include "demo.h"
// #include "led.h"
// #include "diagnostic.h"
// #include "logger.h"
// #include "button.h"
#include "engine.h"
#include "helpers.h"
#include "UID_identity.h"
#include "UID_utils.h"
#include "UID_fillCache.h"
#include "UID_dispatch.h"
#include "UID_capBAC.h"
#ifdef MANAGE_CAPABILITY
	#include "yajl/yajl_tree.h"
#endif //MANAGE_CAPABILITY
#include "mqtt_transport.h"
//#include "btgatt-server.h"
#include "jsmn.h"

#define _EVER_ ;;
//#define MAX_SIZEOF(var1, var2)  ( (sizeof((var1)) > sizeof((var2)) )? sizeof((var1)) : sizeof((var2)) )
//static char buf[MAX_SIZEOF(pIdentity->keyPair.privateKey, pIdentity->keyPair.publicKey)*2+1];
#define DEFAULT_INI_FILE "./demo.ini"
#define DEFAULT_ANNOUNCE_TOPIC "UID/announce"
#define DEFAULT_NAME_PREFIX "METER"

#define linux_logger_write(...)
#define logger_delete(f)
#define led_blink()
#define led_setup()
#define button_setup()
#define button_is_pressed() 0

char *pAnnounceTopic = DEFAULT_ANNOUNCE_TOPIC;
char *pNamePrefix = DEFAULT_NAME_PREFIX;

char node_status = 'C';
int received_capability = 0;

void update_node_status(cache_buffer *cache)
{
	if (0 == cache->validCacheEntries) node_status = 'C'; //created
	if (1 == cache->validCacheEntries)
	{
		if ( 0 == memcmp(cache->contractsCache[0].profile.bit_mask, "\xFF\xFF\xFF\xFF", 4)) node_status = 'I'; //imprinted
		else if (cache->contractsCache[0].profile.bit_mask[3] & 0x40) node_status = 'E'; //enrolled
		else node_status = '*'; //error
	}
	if (1 < cache->validCacheEntries) node_status = 0x30+cache->validCacheEntries-1; //number of contracts
}

extern cache_buffer *capDBp;

// Update Cache Thread
// gets contracts from the BlockChain and updates the local cache
void *updateCache(void *arg)
{
	cache_buffer *cache;
	int fd;
	int ret;

	while(1)
	{
		ret = UID_getContracts(&cache);
		if ( UID_CONTRACTS_OK == ret) {
			fd = creat("ccache.bin", 0666);
			write(fd, cache->contractsCache, sizeof(UID_SecurityProfile)*(cache->validCacheEntries));
			close(fd);

			fd = creat("clicache.bin", 0666);
			write(fd, cache->clientCache, sizeof(UID_ClientProfile)*(cache->validClientEntries));
			close(fd);
		}
		else {
			DBG_Print("UID_getContracts() return %d\n", ret);
		}

	    int i;
	    char buf[161];
	    for (i = 0; i<cache->validCacheEntries;i++) {
	        INFO_Print("[[ %s %s %s ]]\n",
	            cache->contractsCache[i].serviceProviderAddress,
	            cache->contractsCache[i].serviceUserAddress,
	            tohex((uint8_t *)&(cache->contractsCache[i].profile), 80, buf));
	    }
	    pthread_mutex_lock(&(capDBp->in_use));  // lock the resource
	    for (i = 0; i<capDBp->validCacheEntries;i++) {
	        INFO_Print("[[ %s %s %s ]]\n",
	            capDBp->contractsCache[i].serviceProviderAddress,
	            capDBp->contractsCache[i].serviceUserAddress,
	            tohex((uint8_t *)&(capDBp->contractsCache[i].profile), 80, buf));
	    }
	    pthread_mutex_unlock(&(capDBp->in_use));  // unlock the resource
	    for (i = 0; i<cache->validClientEntries;i++) {
	        INFO_Print("[[ %s %s <%s> ]]\n",
	            cache->clientCache[i].serviceProviderAddress,
	            cache->clientCache[i].serviceUserAddress,
	            cache->clientCache[i].serviceProviderName);
	    }
        INFO_Print("\n");

		update_node_status(cache);
		sleep(60);
	}
	return arg;
}

/**
 * Loads the contracts DB from files.
 * ccache.bin contains the provider contracs
 * clicache.bin contains the user contracts
 */
void load_contracts_cache(void)
{
	int fd;

	//load the contracts cache
	extern cache_buffer *current;
	fd = open("ccache.bin", O_RDONLY);
	if (fd >= 0)
	{	// load disk cache
		(current->validCacheEntries)=0;
		while ( sizeof(UID_SecurityProfile) == read(fd, (current->contractsCache) + (current->validCacheEntries), sizeof(UID_SecurityProfile)) )
			(current->validCacheEntries)++;
		close(fd);
	}
	//load the client cache
	//extern cache_buffer *current;
	fd = open("clicache.bin", O_RDONLY);
	if (fd >= 0)
	{	// load disk cache
		(current->validClientEntries)=0;
		while ( sizeof(UID_ClientProfile) == read(fd, (current->clientCache) + (current->validClientEntries), sizeof(UID_ClientProfile)) )
			(current->validClientEntries)++;
		close(fd);
	}
	update_node_status(current);
	INFO_Print("loaded %d valid contracts and %d valid providers from cache\n", current->validCacheEntries, current->validClientEntries);
}


void user_33(char *param, char *result, size_t size)
{
	snprintf(result, size, "you requested: <%s>", param);
}

int method;
int RPCerror;

#define ACCEPT_BUFFER (PARAM_BUFFER + 100)
#define PARAM_BUFFER  1024
#define RESULT_BUFFER (1024*3)
#define RESP_BUFFER   (RESULT_BUFFER + 400)

int MY_perform_request(uint8_t *buffer, size_t size, uint8_t *response, size_t *rsize, UID_ServerChannelCtx *channel_ctx)
{
    int ret;
	int64_t sID;
	char params[PARAM_BUFFER];
    char result[RESULT_BUFFER] = {0}; // must find a better way to allocate the buffer!!!

	method = -1;
	RPCerror = 0;
	// parse the request
	ret = UID_parseReqMsg(buffer, size, &method, params, sizeof(params), &sID);
	if (ret) return ret;

	// check the contract for permission
    if(UID_checkPermission(method, channel_ctx->contract.profile)) {
		if (UID_RPC_RESERVED > method) {
			// Uniquid method. call UID_performRequest
		    RPCerror = UID_performRequest(method, params, result, sizeof(result));
		}
		else {
			// user method.
			switch(method) {
				case 33:
					user_33(params, result, sizeof(result));
					RPCerror = 0;
					break;
				default:
					RPCerror = UID_DISPATCH_NOTEXISTENT;
					break;
			}
		}
    }
    else {
		// no permission for the method
		RPCerror = UID_DISPATCH_NOPERMISSION;
    }


	// format the response message
	ret = UID_formatRespMsg(&channel_ctx->contract.path, result, RPCerror, sID, response, rsize);
	if (ret) return ret;

    return UID_MSG_OK;
}

#ifdef MANAGE_CAPABILITY
/**
 * Check the message for capability
 */
int decodeCapability(uint8_t *msg)
{
	UID_UniquidCapability cap = {0};
	yajl_val node, v;
	int ret = 0;

	const char * assigner[] = { "assigner", (const char *) 0 };
	const char * resourceID[] = { "resourceID", (const char *) 0 };
	const char * assignee[] = { "assignee", (const char *) 0 };
	const char * rights[] = { "rights", (const char *) 0 };
	const char * since[] = { "since", (const char *) 0 };
	const char * until[] = { "until", (const char *) 0 };
	const char * assignerSignature[] = { "assignerSignature", (const char *) 0 };

    // parse message
	node = yajl_tree_parse((char *)msg, NULL, 0);
    if (node == NULL) return 0; // parse error. not a capability

    v = yajl_tree_get(node, assigner, yajl_t_string);
    if (v == NULL) goto clean_return;
    if (sizeof(cap.assigner) <= (size_t)snprintf(cap.assigner, sizeof(cap.assigner), "%s", YAJL_GET_STRING(v)))
		goto clean_return;

    v = yajl_tree_get(node, resourceID, yajl_t_string);
    if (v == NULL) goto clean_return;
    if (sizeof(cap.resourceID) <= (size_t)snprintf(cap.resourceID, sizeof(cap.resourceID), "%s", YAJL_GET_STRING(v)))
		goto clean_return;

    v = yajl_tree_get(node, assignee, yajl_t_string);
    if (v == NULL) goto clean_return;
    if (sizeof(cap.assignee) <= (size_t)snprintf(cap.assignee, sizeof(cap.assignee), "%s", YAJL_GET_STRING(v)))
		goto clean_return;

    v = yajl_tree_get(node, rights, yajl_t_string);
    if (v == NULL) goto clean_return;
	if (sizeof(cap.rights) != fromhex(YAJL_GET_STRING(v), (uint8_t *)&(cap.rights), sizeof(cap.rights)))
		goto clean_return;

    v = yajl_tree_get(node, since, yajl_t_number);
    if (v == NULL) goto clean_return;
	cap.since = YAJL_GET_INTEGER(v);

    v = yajl_tree_get(node, until, yajl_t_number);
    if (v == NULL) goto clean_return;
	cap.until = YAJL_GET_INTEGER(v);

    v = yajl_tree_get(node, assignerSignature, yajl_t_string);
    if (v == NULL) goto clean_return;
    if (sizeof(cap.assignerSignature) <= (size_t)snprintf(cap.assignerSignature, sizeof(cap.assignerSignature), "%s", YAJL_GET_STRING(v)))
		goto clean_return;

	// parsing OK. Will return 1
    ret = 1;

	// receive the capability
	int recv = UID_receiveProviderCapability(&cap);
	if (recv != UID_CAPBAC_OK) {
		DBG_Print("ERROR receiving capability: UID_receiveProviderCapability() returns %d\n", recv);
	}
	else {
		DBG_Print("Valid capability received!!\n");
		received_capability = 2;
	}

clean_return:
    if (NULL != node) yajl_tree_free(node);
    return ret;
}
#endif //MANAGE_CAPABILITY

/**
 * thread implementing a Service Provider
 */
void* service_provider(void *arg)
{
	int ret;

	// Provider infinite loop
	while(1)
	{
		uint8_t *msg;
		size_t size;
		//char *sourceS = "";

		int source = mqttProviderWaitMsg(&msg, &size);

		//if(source == MSG_SOURCE_MQTT) sourceS = "MQTT";
		//if(source == MSG_SOURCE_BLE)  sourceS = "BLE ";

#ifdef MANAGE_CAPABILITY
		if(decodeCapability(msg)) {
			// got capability
			free(msg);
			continue;
		}
#endif //MANAGE_CAPABILITY
		// server
		UID_ServerChannelCtx sctx;
		uint8_t sbuffer[ACCEPT_BUFFER];
		size_t ssize = sizeof(sbuffer);
		ret = UID_accept_channel(msg, size, &sctx, sbuffer, &ssize);

		free(msg);

		if ( UID_MSG_OK != ret) {
			error(0, 0, "UID_accept_channel() return %d\n", ret);
			linux_logger_write(LOG_FILE_NAME, "{\"timestamp\":%" PRId64 ",\"message\":\"(%s) Error %d Accepting request\"}", UID_getTime(), sourceS, ret);
			continue;
		}
		DBG_Print("contract %s %s %d\n", sctx.contract.serviceUserAddress, sctx.contract.serviceProviderAddress, sctx.contract.profile.bit_mask[0]);

		DBG_Print("UID_accept_channel %s -- %zu\n", sbuffer, ssize);
		uint8_t response[RESP_BUFFER];
		size_t respsize = sizeof(response);
		ret = MY_perform_request(sbuffer, ssize, response, &respsize, &sctx);
		linux_logger_write(LOG_FILE_NAME, "{\"timestamp\":%" PRId64 ",\"message\":\"(%s) %s method %d RPCerror %d error %d\"}", UID_getTime(), sourceS, sender, method, RPCerror, ret);
		if ( UID_MSG_OK != ret) {
			error(0, 0, "UID_perform_request() return %d\n", ret);
			continue;
		}
		DBG_Print("UID_perform_request %s - %zu\n", response, respsize);

		if(source == MSG_SOURCE_MQTT) mqttProviderSendMsg(sctx.contract.serviceUserAddress, response, respsize - 1);
//		if(source == MSG_SOURCE_BLE)  ble_send(response,  respsize - 1);


		UID_closeServerChannel(&sctx);
	}

	return arg;
}



#define GOTO_ERROR( ... )  { ERROR_Print( __VA_ARGS__ ); goto err; }

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

char *awsAgentName = NULL;
char *proxyAddress = DEFAULT_PROXY_ADDRESS;
uint32_t proxyPort = DEFAULT_PROXY_PORT;

static bool loadConf(void)
{
    int confFile = 0;
    char *confjson = NULL;
    int i, r;
    jsmn_parser p;
	bool ret = false;
    jsmntok_t t[128]; /* We expect no more than 128 tokens */

    struct stat st;

    if (0 == stat(CONF_FILE, &st)) { // Config file exists
		if ( NULL == (confjson = malloc(st.st_size))) GOTO_ERROR("malloc() failed\n");
		if ((confFile = open(CONF_FILE, O_RDONLY)) < 0) GOTO_ERROR("Error opening confFile %s\n", CONF_FILE);
		if (st.st_size != read(confFile, confjson, st.st_size)) GOTO_ERROR("confFile read() error\n");
	}
	else { // load configuration from environment
		DBG_Print("Config file %s not found. Reading configuration from env\n", CONF_FILE);
		if ( NULL == (confjson = getenv(CONFIG_ENV_VAR))) GOTO_ERROR("Env var %s not exists\n", CONFIG_ENV_VAR);
	}

    jsmn_init(&p);
    r = jsmn_parse(&p, confjson, strlen(confjson), t, sizeof(t)/sizeof(t[0]));
    if (r < 0) GOTO_ERROR("Failed to parse JSON: %d\n", r);

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) GOTO_ERROR("Object expected\n");

    /* Loop over all keys of the root object */
    for (i = 1; i < r; i++) {
        int size =  t[i+1].end-t[i+1].start;
        if (jsoneq(confjson, &t[i], "mqttsUrl") == 0) {
			int start = t[i+1].start;
			int j;
			if (strncmp(confjson + start, "tcp://", 6) == 0) start +=6;
			for (j=start; j<t[i+1].end; j++) if (confjson[j] == ':') break;
            mqtt_address = strndup(confjson + start, j-start);
			sscanf(confjson + 1 + j, "%" SCNd32, &mqtt_port);
        }
        if (jsoneq(confjson, &t[i], "mqttTopic") == 0) {
            pAnnounceTopic = strndup(confjson + t[i+1].start, size);
        }
        if (jsoneq(confjson, &t[i], "registryUrl") == 0) {
            UID_pRegistryURL = strndup(confjson + t[i+1].start, size + 9); // allow space for "/registry"
			strcpy( UID_pRegistryURL + size, "/registry");
        }
        if (jsoneq(confjson, &t[i], "awsAgentName") == 0) {
            awsAgentName = strndup(confjson + t[i+1].start, size);
        }
        if (jsoneq(confjson, &t[i], "network") == 0) {
			if (strncmp(confjson + t[i+1].start, "ltc-testnet", size) == 0)
				UID_pApplianceURL = LTC_TESTNET_APPLIANCE;
			if (strncmp(confjson + t[i+1].start, "ltc-regtest", size) == 0)
				UID_pApplianceURL = LTC_REGTEST_APPLIANCE;
			if (strncmp(confjson + t[i+1].start, "ltc-mainnet", size) == 0)
				UID_pApplianceURL = LTC_MAINNET_APPLIANCE;
        }
        if (jsoneq(confjson, &t[i], "proxyUrl") == 0) {
			int start = t[i+1].start;
			int j;
			if (strncmp(confjson + start, "tcp://", 6) == 0) start +=6;
			for (j=start; j<t[i+1].end; j++) if (confjson[j] == ':') break;
            proxyAddress = strndup(confjson + start, j-start);
			sscanf(confjson + 1 + j, "%" SCNd32, &proxyPort);
        }
    }
	ret = true;
err:
     if (confFile > 0) close(confFile);
	 return ret;
}

const char *linktrezor(void)
{
	extern const char SECP256K1_NAME[];
	return SECP256K1_NAME;
}

void clear_identity(void)
{
	unlink("identity.db");
	unlink("serial.no");
	unlink("ccache.bin");
	unlink("clicache.bin");
	unlink("level");
	led_blink();
}

static char myname[UID_NAME_LENGHT];
static char lbuffer[1024];

/**
 * main - simple demo featuring a "Uniquid Machine" reference implemetation
 */
void uniquidEngine( char *deviceName )
{
	pthread_t thr;

	DBG_Print("Hello!!!!\n");
	capDBp->validCacheEntries = 0; // should be initialized by the lib!!

	if (!loadConf()) {
		ERROR_Print("Cannot load the configuration\n");
		exit(1);
	};

	led_setup();
	button_setup();

	if (button_is_pressed()) clear_identity();

	INFO_Print ("MQTT broker address %s\n", mqtt_address);


	UID_getLocalIdentity(NULL);

	DBG_Print("tpub: %s\n", UID_getTpub());

	snprintf(myname, sizeof(myname), "%s", deviceName);
	DBG_Print("Uniqe name %s\n", myname);
//	set_bt_name(myname);

    // start the mqttWorker thread
	pthread_create(&thr, NULL, mqttWorker, myname);

	snprintf(lbuffer, sizeof(lbuffer), "{\"name\":\"%s\",\"xpub\":\"%s\"}", myname, UID_getTpub());

	// Send imprinting message
	mqttProviderSendMsg(pAnnounceTopic, (uint8_t *)lbuffer, strlen(lbuffer));
	DBG_Print("%s\n", lbuffer);

	load_contracts_cache();
	// start the the thread that updates the 
	// contracts cache from the blockchiain
	pthread_create(&thr, NULL, updateCache, NULL);

//	// start the demo thread
//	pthread_create(&thr, NULL, demo, NULL);

	// start the "provider" thread
	pthread_create(&thr, NULL, service_provider, NULL);

	logger_delete(LOG_FILE_NAME);

//	for(_EVER_) ble_start(NULL);

//	for(_EVER_) sleep(100); // wait for ever

//	exit( 0 );
}

