/* Copyright (C) 2015-2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author XXX Yourname <youremail@yourdomain>
 */

#ifndef __DETECT_S7COMM_H__
#define __DETECT_S7COMM_H__

/** Per keyword data. This is set up by the DetectS7commSetup() function.
 *  Each signature will have an instance of DetectS7commData per occurence
 *  of the keyword.
 *  The structure should be considered static/readonly after initialization.
 */
typedef struct DetectS7commData_ {
    uint8_t arg1;
    uint8_t arg2;
} DetectS7commData;		//похоже на струкутру, в которую закидывается инфа, по которой мы поймем, что совпало с правилом

/** \brief registers the keyword into the engine. Called from
 *         detect.c::SigTableSetup() */
void DetectS7commRegister(void);	//как понимаю надо прописать ее detect.c

#endif /* __DETECT_S7COMM_H__ */
