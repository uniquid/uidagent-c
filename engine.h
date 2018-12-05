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

void uniquidEngine( void );
uint8_t *signedTimestamp(uint8_t *token, size_t tokenLen, char *provider);

#endif //__ENGINE_H__