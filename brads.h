#ifndef BRADS_H
#define BRADS_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <sys/types.h>

#include "kernel/fs.h"

// BRADS Debugging

extern lock_t bradsdebuglock;

extern struct mount *rootmount;
extern char rootsource[4096];
char *rootsource2 = "/Users/bbarrows/Library/Developer/CoreSimulator/Devices/AE9BC6B8-42E1-472E-8FCF-DDB7F6DB0D06/data/Containers/Shared/AppGroup/229101E0-7242-43FD-AB5F-A8644E5005E6/";

#endif
