/*
 * engine.h
 *
 *  Created on: 11/nov/2018
 *      Author: M. Palumbi
 */
 
 

#pragma once
#ifndef __ENGINE_H__
#define __ENGINE_H__
#include <stdint.h>

void uniquidEngine( void );
uint8_t *signedTimestamp(uint8_t *token, size_t tokenLen, char *provider);

#endif //__ENGINE_H__