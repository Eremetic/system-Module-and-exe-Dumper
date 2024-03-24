#pragma once
#include "Globals.h"



#define _DLL_COUNT 9


BOOL UnHook_Dlls(IN int name);

VOID IatCamouflage();

//constexpr ULONG ExprXorKey(
//    VOID
//) {
//    return '0' * -40271 +
//        __TIME__[7] * 1 +
//        __TIME__[6] * 10 +
//        __TIME__[4] * 60 +
//        __TIME__[3] * 600 +
//        __TIME__[1] * 3600 +
//        __TIME__[0] * 36000;
//}




//constexpr uint32_t modulus()
//{
//    return 0x7fffffff;
//}
//
//template<size_t N>
//constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
//    auto value{ iv };
//    for (size_t i{ 0 }; i < N; i++) {
//
//        value = (value & ((~0) << 8)) | ((value & 0xFF) ^ entropy[i]);
//
//        value = value << 8 | value >> ((sizeof(value) * 8) - 8);
//    }
//
//    while (value > modulus()) value = value >> 1;
//    return value << 1 | 1;
//}
//
//constexpr uint32_t prng(const uint32_t input) {
//    return (input * 48271) % modulus();
//}
//
//ULONG KeyXorObf = seed(__FILE__, ExprXorKey());
//
