/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

/*
 * @file   token.c
 *
 * @date   29/nov/2018
 * @author M. Palumbi
 */


/**
 * @file engine.h
 *
 * UniquID auth token
 *
 */

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include "UID_bchainBTC.h"
#include "UID_time.h"
#include "UID_utils.h"
#include "engine.h"

/**
 * Build the token for the UniquID authentication
 * token has this form:
 * 4 bites header (uint32_t) representing the lenght of the next field (null terminator comprised)
 * a null terminated string in this form {"userAddress":"address","timestamp":time,"signature":"base64 signature"}
 * where:
 * address          is the userAddress of the UniqID contract
 * time             is the current time in milliseconds
 * base64 signature is the signature base64 coded of the stringified timestamp using the private key relative to userAddress
 *
 * @param[out] token     pointer to a buffer where to store the token
 * @param[in]  tokenLen  length of the buffer
 * @param[in]  provider  provider name of the contract to use
 *
 * @return     the address of the token or NULL on failure
 *             if contract doesnt exists the string token will be
 *             {"userAddress":"noaddress","timestamp":time,"signature":""}
 */
uint8_t *signedTimestamp(uint8_t *token, size_t tokenLen, char *provider)
{
    UID_ClientProfile *contract;
    char timeString[32];
    char signature[256] = {0};
    char *serviceUserAddress = "noaddress";


    if(tokenLen < 5) return NULL; // not enogh space
    uint32_t *header = (uint32_t *)token;
    token += 4;
    tokenLen -= 4;

    snprintf(timeString, sizeof(timeString), "%"  PRId64 "", UID_getTime());

    contract = UID_matchProvider(provider);
    if (contract)
    {
        UID_signMessage(timeString, &(contract->path), signature, sizeof(signature));
        serviceUserAddress = contract->serviceUserAddress;
    }
    uint toprint = snprintf((char *)token, tokenLen,
        "{\"userAddress\":\"%s\",\"timestamp\":%s,\"signature\":\"%s\"}",
            serviceUserAddress, timeString, signature);
    *header = (toprint < tokenLen) ? toprint + 1 : tokenLen ;
    return token;
}