#include <stdio.h>
#include <stdint.h>

enum r8 {
	AL = 0,
	CL,
	DL,
	BL,
	AH,
	CH,
	DH,
	BH,
};

enum r16 {
	AX = 0,
	CX,
	DX,
	BX,
	SP,
	BP,
	SI,
	DI,
};

enum r32 {
	EAX = 0,
	ECX,
	EDX,
	EBX,
	ESP = 4,
	// used in sib
	ENONE = 4,
	EBP,
	ESI,
	EDI,
};

enum r64 {
	RAX = 0,
	RCX,
	RDX,
	RBX,
	RSP = 4,
	// used in sib
	RNONE = 4,
	RBP,
	RSI,
	RDI,
};

enum xr64 {
	R8 = 0,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
};

enum mm {
	MM0 = 0,
	MM1,
	MM2,
	MM3,
	MM4,
	MM5,
	MM6,
	MM7,
};

enum xmm {
	XMM0 = 0,
	XMM1,
	XMM2,
	XMM3,
	XMM4,
	XMM5,
	XMM6,
	XMM7,
};

typedef enum  {
	effect_none = 0,
	effect_OP1,
	effect_OP2,
} effect_t;

typedef enum {
	disp_none = 8,
	disp8,
	disp32,
} displace_t;

struct MODRM {
	unsigned int mod : 2;
	// in other words, /digit
	unsigned int reg : 3;
	unsigned int rm : 3;
};

struct SIB {
	unsigned int ss : 2;
	unsigned int index : 3;
	unsigned int base : 3;
};

typedef enum {
	CALC_FAILED = -1,
	CALC_SUCCESS = 0,
	CALC_SUCCESS_HAS_SIB = 1,
} CALC_RESP;

// INTEL MANUAL VOLUME 2, CH 2.1.5
CALC_RESP calc_modrm_x64(int op1, int op2, effect_t which, int disp, struct MODRM *modrm);
CALC_RESP calc_sib_x64(int scale_index, int base, int scale, struct SIB *sib);

uint8_t modrm_to_byte(struct MODRM modrm);
uint8_t sib_to_byte(struct SIB sib);
