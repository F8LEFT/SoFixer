//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/9/13.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#ifndef SOFIXER_FDEBUG_H
#define SOFIXER_FDEBUG_H

extern bool FDebug;

#define FLOGE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define FLOGD(fmt, ...) if(FDebug) printf(fmt, ##__VA_ARGS__)


#endif //SOFIXER_FDEBUG_H
