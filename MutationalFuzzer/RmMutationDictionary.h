
#pragma once

#include "Mutations.h"

#define PN_SAVE_ENABLED 0x0001
#define PN_PERFECT_PLAY_ENABLED 0x0002
#define PN_LIVE_BROADCAST 0x0004

#define PN_RELIABLE_FLAG 0x0001
#define PN_KEYFRAME_FLAG 0x0002

#ifndef PN_FOURCC
#define PN_FOURCC( ch0, ch1, ch2, ch3 )                                    \
                ( (UINT32)(UINT8)(ch0) | ( (UINT32)(UINT8)(ch1) << 8 ) |        \
                ( (UINT32)(UINT8)(ch2) << 16 ) | ( (UINT32)(UINT8)(ch3) << 24 ) )
#endif

__MUTATION RM_MUTATIONS[] =
{
	{ MUTATE_OVERWRITE_WORD, 0x00, PN_SAVE_ENABLED, 0x00000000, NULL, 0 },
	{ MUTATE_OVERWRITE_WORD, 0x00, PN_PERFECT_PLAY_ENABLED, 0x00000000, NULL, 0 },
	{ MUTATE_OVERWRITE_WORD, 0x00, PN_LIVE_BROADCAST, 0x00000000, NULL, 0 },
	{ MUTATE_OVERWRITE_DWORD, 0x00, 0x0000, PN_FOURCC('.', 'R', 'M', 'F'), NULL, 0 },
	{ MUTATE_OVERWRITE_DWORD, 0x00, 0x0000, PN_FOURCC('P', 'R', 'O', 'P'), NULL, 0 },
	{ MUTATE_OVERWRITE_DWORD, 0x00, 0x0000, PN_FOURCC('M', 'D', 'P', 'R'), NULL, 0 },
	{ MUTATE_OVERWRITE_DWORD, 0x00, 0x0000, PN_FOURCC('C', 'O', 'N', 'T'), NULL, 0 },
	{ MUTATE_OVERWRITE_DWORD, 0x00, 0x0000, PN_FOURCC('D', 'A', 'T', 'A'), NULL, 0 },
	{ MUTATE_OVERWRITE_WORD, 0x00, PN_RELIABLE_FLAG, 0x00000000, NULL, 0 },
	{ MUTATE_OVERWRITE_WORD, 0x00, PN_KEYFRAME_FLAG, 0x00000000, NULL, 0 },
	{ MUTATE_OVERWRITE_DWORD, 0x00, 0x0000, PN_FOURCC('I', 'N', 'D', 'X'), NULL, 0 },
	{ MUTATE_END,  0x00, 0x0000, 0x00000000, NULL, 0 }
};

