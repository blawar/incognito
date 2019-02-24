/**
 * @file bpc.h
 * @brief Board power control (bpc) service IPC wrapper.
 * @author XorTroll
 * @copyright libnx Authors
 */
#pragma once
#include <switch/types.h>

extern "C" {
Result bpcInitialize(void);
void bpcExit(void);

Result bpcShutdownSystem(void);
Result bpcRebootSystem(void);
};