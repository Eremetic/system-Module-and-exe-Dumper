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


///compile time wide string encryption
constexpr ULONG ObfXorKey = ExprXorKey();

template<size_t N>
struct WObjStringObf {
    WCHAR Buffer[N];
};

template<size_t N>
constexpr auto WObfucate(
    _In_ CONST wchar_t(&Buffer)[N]
) {
    WObjStringObf<N> String{};

    for (int i = 0; i < N; i++) {
        String.Buffer[i] = Buffer[i] ^ ObfXorKey;
    }

    return String;
}

#define WStringObf( STRING ) ( [&] {              \
    constexpr auto TempStr = WObfucate( STRING ); \
    return WObfucate( TempStr.Buffer ).Buffer;    \
}() )



/// compile time string excryption
template<size_t N>
struct ObjStringObf {
    CHAR Buffer[N];
};

template<size_t N>
constexpr auto Obfucate(
    _In_ CONST CHAR(&Buffer)[N]
) {
    ObjStringObf<N> String{};

    for (int i = 0; i < N; i++) {
        String.Buffer[i] = Buffer[i] ^ ObfXorKey;
    }

    return String;
}

#define StringObf( STRING ) ( [&] {              \
    constexpr auto TempStr = Obfucate( STRING ); \
    return Obfucate( TempStr.Buffer ).Buffer;    \
}() )