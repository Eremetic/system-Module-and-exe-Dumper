#pragma once
#include "Globals.h"



#define _DLL_COUNT 9


BOOL UnHook_Dlls(IN int name);




constexpr ULONG ExprXorKey(
    VOID
) {
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

constexpr ULONG ObfXorKey = ExprXorKey();

template<size_t N>
struct ObjStringObf {
    char Buffer[N];
};

template<size_t N>
constexpr auto Obfucate(const char(&Buffer)[N], ULONG Key) {
    ObjStringObf<N> String{};

    for (int i = 0; i < N; i++) {
        String.Buffer[i] = Buffer[i] ^ Key;
    }

    return String;
}

#define StringObf( STRING ) ( [&] {              \
    constexpr auto TempStr = Obfucate( STRING, ObfXorKey ); \
    return Obfucate( TempStr.Buffer , ObfXorKey).Buffer;    \
}() )




