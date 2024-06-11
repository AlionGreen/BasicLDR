#pragma once
#include "utils.h"

#define H_MAGIC_KEY       53821
#define H_MAGIC_SEED      15


#define HASH_STR( x ) ( ExprHashStringA ( x ) )
constexpr ULONG ExprHashStringA(_In_ PCHAR String);


constexpr ULONG ExprHashStringA(
	_In_ PCHAR String
) {
	ULONG Hash = { 0 };
	CHAR  Char = { 0 };

	Hash = H_MAGIC_KEY;

	if (!String) {
		return 0;
	}

	while ((Char = *String++)) {
		/* turn current character to uppercase */
		if (Char >= 'a') {
			Char -= 0x20;
		}

		Hash = ((Hash << H_MAGIC_SEED) + Hash) + Char;
	}

	return Hash;
}

