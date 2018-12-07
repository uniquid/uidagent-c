/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

/**
 * @file   engine.h
 *
 * @date   11/nov/2018
 * @author M. Palumbi
 */
 
 

#pragma once
#ifndef __ENGINE_H__
#define __ENGINE_H__
#include <stdint.h>

#define CONF_FILE "virtual_device_cfg.json"
#define LTC_TESTNET_APPLIANCE "http://40.115.38.96:3001/insight-lite-api"
#define LTC_REGTEST_APPLIANCE "http://40.115.38.96:3001/insight-lite-api"
#define LTC_MAINNET_APPLIANCE "http://40.115.38.96:3001/insight-lite-api"

#define DEFAULT_PROXY_ADDRESS "127.0.0.1"
#define DEFAULT_PROXY_PORT    8883

extern char *awsAgentName;
extern char *proxyAddress; // = DEFAULT_PROXY_ADDRESS;
extern uint32_t proxyPort; // = DEFAULT_PROXY_PORT;


void uniquidEngine( char *deviceName );
uint8_t *signedTimestamp(uint8_t *token, size_t tokenLen, char *provider);

#endif //__ENGINE_H__