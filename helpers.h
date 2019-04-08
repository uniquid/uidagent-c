/*
 * Copyright (c) 2016-2018. Uniquid Inc. or its affiliates. All Rights Reserved.
 *
 * License is in the "LICENSE" file accompanying this file.
 * See the License for the specific language governing permissions and limitations under the License.
 */

/**
 * @file   helpers.h
 *
 * @date   29/lug/2016
 * @author M. Palumbi
 */



#pragma once
#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <stdint.h>

#define ENABLE_DBG_PRINT
#define ENABLE_ERROR_PRINT
#define ENABLE_INFO_PRINT


#ifdef ENABLE_DBG_PRINT
#define DBG_Print( ... ) \
    { \
    printf("DBG:   %s L#%d ", __func__, __LINE__);  \
    printf(__VA_ARGS__); \
    }
#else
    #define DBG_Print( ... )
#endif

#ifdef ENABLE_ERROR_PRINT
#define ERROR_Print( ... ) \
    { \
    printf("ERROR: %s L#%d ", __func__, __LINE__);  \
    printf(__VA_ARGS__); \
    }
#else
    #define ERROR_Print( ... )
#endif

#ifdef ENABLE_INFO_PRINT
#define INFO_Print( ... ) \
    { \
    printf(__VA_ARGS__); \
    }
#else
    #define INFO_Print( ... )
#endif

extern char *program_name;

/* error - print a diagnostic and optionally exit */
void error( int status, int err, char *fmt, ... );


// socket IO functions
ssize_t readLine(int fd, void *buffer, size_t n);
ssize_t ReadXBytes(int socket, void* buffer, unsigned int x);
int WriteXBytes(const int sock, const char *const buffer, const size_t buflen);

uint8_t *getSerial( void );

void LOG_print( char *fmt, ... );

#endif