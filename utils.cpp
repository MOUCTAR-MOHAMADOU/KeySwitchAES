#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>
#include "utils.hpp"

void HexToBinStr(int hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        bin_str[i] = hex % 2;
        hex /= 2;
    }
}

void BinStrToHex(int &dec_hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        dec_hex += bin_str[i] * pow(2, i);
    }
}