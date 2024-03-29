/*
 * Copyright (c) 2016-2022, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <arch.h>
#include <asm_macros.S>
#include <bl_common.h>
#include <cortex_a73.h>
#include <cpu_macros.S>
#include <plat_macros.S>

	/* ---------------------------------------------
	 * Disable L1 data cache
	 * ---------------------------------------------
	 */
func cortex_a73_disable_dcache
	mrs	x1, sctlr_el3
	bic	x1, x1, #SCTLR_C_BIT
	msr	sctlr_el3, x1
	isb
	ret
endfunc cortex_a73_disable_dcache

	/* ---------------------------------------------
	 * Disable intra-cluster coherency
	 * ---------------------------------------------
	 */
func cortex_a73_disable_smp
	mrs	x0, CORTEX_A73_ECTLR_EL1
	bic	x0, x0, #CORTEX_A73_ECTLR_SMP_BIT
	msr	CORTEX_A73_ECTLR_EL1, x0
	isb
	dsb	sy
	ret
endfunc cortex_a73_disable_smp

func cortex_a73_reset_func
	mov	x19, x30
	bl	cpu_get_rev_var
	mov	x18, x0

#if ERRATA_A73_852427
	mov	x0, x18
	bl	errata_a73_852427_wa
#endif

#if ERRATA_A73_855423
	mov	x0, x18
	bl	errata_a73_855423_wa
#endif

#if IMAGE_BL31 && (WORKAROUND_CVE_2017_5715 || WORKAROUND_CVE_2022_23960)
	cpu_check_csv2	x0, 1f
	adr	x0, wa_cve_2017_5715_bpiall_vbar
	msr	vbar_el3, x0
	isb
	/* Skip installing vector table again for CVE_2022_23960 */
        b       2f
1:
#if WORKAROUND_CVE_2022_23960
	adr	x0, wa_cve_2017_5715_bpiall_vbar
	msr	vbar_el3, x0
	isb
#endif
2:
#endif /* IMAGE_BL31 &&  (WORKAROUND_CVE_2017_5715 || WORKAROUND_CVE_2022_23960) */

#if WORKAROUND_CVE_2018_3639
	mrs	x0, CORTEX_A73_IMP_DEF_REG1
	orr	x0, x0, #CORTEX_A73_IMP_DEF_REG1_DISABLE_LOAD_PASS_STORE
	msr	CORTEX_A73_IMP_DEF_REG1, x0
	isb
#endif

	/* ---------------------------------------------
	 * Enable the SMP bit.
	 * Clobbers : x0
	 * ---------------------------------------------
	 */
	mrs	x0, CORTEX_A73_CPUECTLR_EL1
	orr	x0, x0, #CORTEX_A73_CPUECTLR_SMP_BIT
	msr	CORTEX_A73_CPUECTLR_EL1, x0
	isb
	ret
endfunc cortex_a73_reset_func

func cortex_a73_core_pwr_dwn
	mov	x18, x30

	/* ---------------------------------------------
	 * Turn off caches.
	 * ---------------------------------------------
	 */
	bl	cortex_a73_disable_dcache

	/* ---------------------------------------------
	 * Flush L1 caches.
	 * ---------------------------------------------
	 */
	mov	x0, #DCCISW
	bl	dcsw_op_level1

	/* ---------------------------------------------
	 * Come out of intra cluster coherency
	 * ---------------------------------------------
	 */
	mov	x30, x18
	b	cortex_a73_disable_smp
endfunc cortex_a73_core_pwr_dwn

func cortex_a73_cluster_pwr_dwn
	mov	x18, x30

	/* ---------------------------------------------
	 * Turn off caches.
	 * ---------------------------------------------
	 */
	bl	cortex_a73_disable_dcache

	/* ---------------------------------------------
	 * Flush L1 caches.
	 * ---------------------------------------------
	 */
	mov	x0, #DCCISW
	bl	dcsw_op_level1

	/* ---------------------------------------------
	 * Disable the optional ACP.
	 * ---------------------------------------------
	 */
	bl	plat_disable_acp

	/* ---------------------------------------------
	 * Flush L2 caches.
	 * ---------------------------------------------
	 */
	mov	x0, #DCCISW
	bl	dcsw_op_level2

	/* ---------------------------------------------
	 * Come out of intra cluster coherency
	 * ---------------------------------------------
	 */
	mov	x30, x18
	b	cortex_a73_disable_smp
endfunc cortex_a73_cluster_pwr_dwn

func check_errata_cve_2017_5715
#if WORKAROUND_CVE_2017_5715
	mov	x0, #ERRATA_APPLIES
#else
	mov	x0, #ERRATA_MISSING
#endif
	ret
endfunc check_errata_cve_2017_5715

func check_errata_cve_2018_3639
#if WORKAROUND_CVE_2018_3639
	mov	x0, #ERRATA_APPLIES
#else
	mov	x0, #ERRATA_MISSING
#endif
	ret
endfunc check_errata_cve_2018_3639

func check_errata_cve_2022_23960
#if WORKAROUND_CVE_2017_5715 || WORKAROUND_CVE_2022_23960
	cpu_check_csv2	x0, 1f
	mov	x0, #ERRATA_APPLIES
	ret
 1:
# if WORKAROUND_CVE_2022_23960
	mov	x0, #ERRATA_APPLIES
# else
	mov	x0, #ERRATA_MISSING
# endif /* WORKAROUND_CVE_2022_23960 */
	ret
#endif /* WORKAROUND_CVE_2017_5715 || WORKAROUND_CVE_2022_23960 */
	mov	x0, #ERRATA_MISSING
	ret
endfunc check_errata_cve_2022_23960

func check_smccc_arch_workaround_3
	mov	x0, #ERRATA_APPLIES
	ret
endfunc check_smccc_arch_workaround_3

#if REPORT_ERRATA
/*
 * Errata printing function for Cortex A75. Must follow AAPCS.
 */
func cortex_a73_errata_report
	stp	x8, x30, [sp, #-16]!

	bl	cpu_get_rev_var
	mov	x8, x0

	/*
	 * Report all errata. The revision-variant information is passed to
	 * checking functions of each errata.
	 */
	report_errata WORKAROUND_CVE_2017_5715, cortex_a73, cve_2017_5715
	report_errata WORKAROUND_CVE_2018_3639, cortex_a73, cve_2018_3639
	report_errata WORKAROUND_CVE_2022_23960, cortex_a73, cve_2022_23960

	ldp	x8, x30, [sp], #16
	ret
endfunc cortex_a73_errata_report
#endif

	/* ---------------------------------------------
	 * This function provides cortex_a73 specific
	 * register information for crash reporting.
	 * It needs to return with x6 pointing to
	 * a list of register names in ascii and
	 * x8 - x15 having values of registers to be
	 * reported.
	 * ---------------------------------------------
	 */
.section .rodata.cortex_a73_regs, "aS"
cortex_a73_regs:  /* The ascii list of register names to be reported */
	.asciz	"cpuectlr_el1", "l2merrsr_el1", ""

func cortex_a73_cpu_reg_dump
	adr	x6, cortex_a73_regs
	mrs	x8, CORTEX_A73_CPUECTLR_EL1
	mrs	x9, CORTEX_A73_L2MERRSR_EL1
	ret
endfunc cortex_a73_cpu_reg_dump

declare_cpu_ops_wa cortex_a73, CORTEX_A73_MIDR, \
	cortex_a73_reset_func, \
	check_errata_cve_2017_5715, \
	CPU_NO_EXTRA2_FUNC, \
	check_smccc_arch_workaround_3, \
	cortex_a73_core_pwr_dwn, \
	cortex_a73_cluster_pwr_dwn
