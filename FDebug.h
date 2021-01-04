//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2018/7/4.
//                   Copyright (c) 2018. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#ifndef ANDDBG_ALOG_H
#define ANDDBG_ALOG_H

//#if !defined(NDEBUG)
#if true

#define TOSTR(fmt) #fmt
#define FLFMT TOSTR([%s:%d])
#define FNLINE TOSTR(\n)

#define FLOGE(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGD(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGW(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGI(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGV(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define FLOGE(fmt, ...)
#define FLOGD(fmt, ...)
#define FLOGW(fmt, ...)
#define FLOGI(fmt, ...)
#define FLOGV(fmt, ...)
#endif

#endif //ANDDBG_ALOG_H
