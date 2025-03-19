// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wintrust.lib")
#endif //PCH_H
