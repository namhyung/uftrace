#include <stdio.h>
#include <stdint.h>
#include "x64_modrm.h"

uint8_t modrm_to_byte(struct MODRM modrm)
{
	uint8_t res = 0;

	res |= (modrm.mod << 6);
	res |= (modrm.reg << 3);
	res |= modrm.rm;

	return res;
}

uint8_t sib_to_byte(struct SIB sib)
{
	uint8_t res = 0;

	res |= (sib.ss << 6);
	res |= (sib.index << 3);
	res |= sib.base;

	return res;
}


// INTEL MANUAL VOLUME 2, CH 2.1.5
CALC_RESP calc_modrm_x64(int op1, int op2, effect_t which, int disp, struct MODRM *modrm)
{
	int cols = -1, rows = -1;
	CALC_RESP res = CALC_FAILED;

	/*
	 * as effective address,
	 * - disp32 only available when disp has none.
	 * - and it must be the effective address cannot be reg value.
	 *
	 * if condition true,
	 * adjust origin value 10 of disp32 to 5 to fit its position.
	 */
	if (disp == disp_none) {
		if (which == effect_OP1 && op1 == disp32)
			op1 -= 5;
		else if (which == effect_OP2 && op2 == disp32)
			op2 -= 5;
	}

	/*
	 * santiny check, correct value range of arguments
	 */
	if (op1 < 0 || op2 < 0 || op1 > 7 || op2 > 7 ||
	    disp < disp_none || disp > disp32 ||
	    which < effect_none || which > effect_OP2) {
		goto FAILED;
	}

	if (which == effect_none) {
		if (disp != disp_none) {
			goto FAILED;
		}

		rows = op1;
		cols = op2;

		modrm->mod = 3;
		modrm->rm = rows;
		modrm->reg = cols;

		return CALC_SUCCESS;

	} else if (which == effect_OP1) {
		rows = op1;
		cols = op2;
	} else {
		rows = op2;
		cols = op1;
	}

	res = CALC_SUCCESS;

	if (disp == disp_none) {
		modrm->mod = 0;

		/*
		 * need to calc SIB addressing
		 */
		if (rows == 4) {
			// SP, ESP, RSP
			res = CALC_SUCCESS_HAS_SIB;
		}
		if (rows == 5) {
			// disp32
			res = CALC_SUCCESS_HAS_SIB;
		}
	}
	else if (disp == disp8) {
		modrm->mod = 1;

		// need to calc SIB addressing
		if (rows == 4) {
			// SP, ESP, RSP
			res = CALC_SUCCESS_HAS_SIB;
		}
	}
	else if (disp == disp32) {
		modrm->mod = 2;

		// need to calc SIB addressing
		if (rows == 4) {
			// SP, ESP, RSP
			res = CALC_SUCCESS_HAS_SIB;
		}
	}

	modrm->rm = rows;
	modrm->reg = cols;

	return res;

FAILED:
	return CALC_FAILED;
}

CALC_RESP calc_sib_x64(int base, int scale_index, int scale, struct SIB *sib)
{
	CALC_RESP res;

	if (scale == 1) {
		sib->ss = 0;
	} else if (scale == 2) {
		sib->ss = 1;
	} else if (scale == 4) {
		sib->ss = 2;
	} else if (scale == 8) {
		sib->ss = 3;
	} else {
		res = CALC_FAILED;
	}

	sib->index = scale_index;
	sib->base = base;

	return res;
}
