/*
 * uftrace.h header file
 *
 * Copyright (C) 2018-2019, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef UFTRACE_H
#define UFTRACE_H

#if defined(__clang__)
#define __uft_disable_opt __attribute__((optnone))
#elif defined(__GNUC__)
#define __uft_disable_opt __attribute__((optimize(0)))
#else
#define __uft_disable_opt
#endif

#define __uft_unused __attribute__((unused))

#define __uft_func __uft_disable_opt __uft_unused

#ifdef __cplusplus
extern "C" {
#endif
/* for explicit mcount() call in user functions */
void __attribute__((weak)) mcount(void);

/* apply "trace_on" trigger */
__uft_func static void uftrace_trace_on(void) {}

/* apply "trace_off" trigger */
__uft_func static void uftrace_trace_off(void) {}

/* apply "finish" trigger */
__uft_func static void uftrace_trace_finish(void) {}
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

/* apply "trace_on"/"trace_off" triggers at ctor/dtor */
class uftrace_trace_block {
public:
  __uft_func uftrace_trace_block()  {}
  __uft_func ~uftrace_trace_block() {}
};

template <typename T>
__uft_func
static void uftrace_print(__uft_unused const char *X, T)
{
}

__uft_func
static void uftrace_print(__uft_unused const char *X, const char* s)
{
	__uft_unused volatile const char c = *s;
}

#define uftrace_print(X) uftrace_print(#X, X)


#else /* #ifdef __cplusplus */


#if __STDC_VERSION__ >= 201112L
/* _Generic is supported from C11 */
#define uftrace_print(X) _Generic((X),                                         \
			char:               _ZL13uftrace_printPKcc,            \
			double:             _ZL13uftrace_printPKcd,            \
			long double:        _ZL13uftrace_printPKce,            \
			float:              _ZL13uftrace_printPKcf,            \
			unsigned char:      _ZL13uftrace_printPKch,            \
			int:                _ZL13uftrace_printPKci,            \
			unsigned int:       _ZL13uftrace_printPKcj,            \
			long:               _ZL13uftrace_printPKcl,            \
			unsigned long:      _ZL13uftrace_printPKcm,            \
			short:              _ZL13uftrace_printPKcs,            \
			unsigned short:     _ZL13uftrace_printPKct,            \
			long long:          _ZL13uftrace_printPKcx,            \
			unsigned long long: _ZL13uftrace_printPKcy,            \
			char*:              _ZL13uftrace_printPKcPc,           \
			const char*:        _ZL13uftrace_printPKcS0_,          \
			default:            _ZL13uftrace_printPKcPKvz)(#X, X)

/* primitive types */
__uft_func static void _ZL13uftrace_printPKcc(const char *X, char a)               {}
__uft_func static void _ZL13uftrace_printPKcd(const char *X, double a)             {}
__uft_func static void _ZL13uftrace_printPKce(const char *X, long double a)        {}
__uft_func static void _ZL13uftrace_printPKcf(const char *X, float a)              {}
__uft_func static void _ZL13uftrace_printPKch(const char *X, unsigned char a)      {}
__uft_func static void _ZL13uftrace_printPKci(const char *X, int a)                {}
__uft_func static void _ZL13uftrace_printPKcj(const char *X, unsigned int a)       {}
__uft_func static void _ZL13uftrace_printPKcl(const char *X, long a)               {}
__uft_func static void _ZL13uftrace_printPKcm(const char *X, unsigned long a)      {}
__uft_func static void _ZL13uftrace_printPKcs(const char *X, short a)              {}
__uft_func static void _ZL13uftrace_printPKct(const char *X, unsigned short a)     {}
__uft_func static void _ZL13uftrace_printPKcx(const char *X, long long a)          {}
__uft_func static void _ZL13uftrace_printPKcy(const char *X, unsigned long long a) {}

/* string types */
__uft_func static void _ZL13uftrace_printPKcPc(const char *X, char *s)             {}
__uft_func static void _ZL13uftrace_printPKcS0_(const char *X, const char *s)      {}

/* default case */
__uft_func static void _ZL13uftrace_printPKcPKvz(const char *X, const void * const a, ...) {}
#else
#warning "uftrace_print is not supported. Please try again with -std=c11"
#define uftrace_print(X)
#endif

#endif /* #ifdef __cplusplus */


#undef __uft_func
#undef __uft_disable_opt
#undef __uft_unused

#endif /* UFTRACE_H */
