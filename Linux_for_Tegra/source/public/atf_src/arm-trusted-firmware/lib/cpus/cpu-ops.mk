#
# Copyright (c) 2014-2018, ARM Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# Cortex A57 specific optimisation to skip L1 cache flush when
# cluster is powered down.
SKIP_A57_L1_FLUSH_PWR_DWN	?=0

# Flag to disable the cache non-temporal hint.
# It is enabled by default.
A53_DISABLE_NON_TEMPORAL_HINT	?=1

# Flag to disable the cache non-temporal hint.
# It is enabled by default.
A57_DISABLE_NON_TEMPORAL_HINT	?=1

# Flag to enable higher performance non-cacheable load
# forwarding
A57_ENABLE_NONCACHEABLE_LOAD_FWD	?= 0

WORKAROUND_CVE_2017_5715	?=1
WORKAROUND_CVE_2018_3639	?=1
DYNAMIC_WORKAROUND_CVE_2018_3639	?=0
WORKAROUND_CVE_2022_23960		?=1

# Process A57_ENABLE_NONCACHEABLE_LOAD_FWD flag
$(eval $(call assert_boolean,A57_ENABLE_NONCACHEABLE_LOAD_FWD))
$(eval $(call add_define,A57_ENABLE_NONCACHEABLE_LOAD_FWD))

# Process SKIP_A57_L1_FLUSH_PWR_DWN flag
$(eval $(call assert_boolean,SKIP_A57_L1_FLUSH_PWR_DWN))
$(eval $(call add_define,SKIP_A57_L1_FLUSH_PWR_DWN))

# Process A53_DISABLE_NON_TEMPORAL_HINT flag
$(eval $(call assert_boolean,A53_DISABLE_NON_TEMPORAL_HINT))
$(eval $(call add_define,A53_DISABLE_NON_TEMPORAL_HINT))

# Process A57_DISABLE_NON_TEMPORAL_HINT flag
$(eval $(call assert_boolean,A57_DISABLE_NON_TEMPORAL_HINT))
$(eval $(call add_define,A57_DISABLE_NON_TEMPORAL_HINT))

# Process WORKAROUND_CVE_2017_5715 flag
$(eval $(call assert_boolean,WORKAROUND_CVE_2017_5715))
$(eval $(call add_define,WORKAROUND_CVE_2017_5715))

# Process WORKAROUND_CVE_2018_3639 flag
$(eval $(call assert_boolean,WORKAROUND_CVE_2018_3639))
$(eval $(call add_define,WORKAROUND_CVE_2018_3639))

$(eval $(call assert_boolean,DYNAMIC_WORKAROUND_CVE_2018_3639))
$(eval $(call add_define,DYNAMIC_WORKAROUND_CVE_2018_3639))

# Process WORKAROUND_CVE_2022_23960 flag
$(eval $(call assert_boolean,WORKAROUND_CVE_2022_23960))
$(eval $(call add_define,WORKAROUND_CVE_2022_23960))

ifneq (${DYNAMIC_WORKAROUND_CVE_2018_3639},0)
    ifeq (${WORKAROUND_CVE_2018_3639},0)
        $(error "Error: WORKAROUND_CVE_2018_3639 must be 1 if DYNAMIC_WORKAROUND_CVE_2018_3639 is 1")
    endif
endif

# CPU Errata Build flags.
# These should be enabled by the platform if the erratum workaround needs to be
# applied.

# Flag to apply erratum 826319 workaround during reset. This erratum applies
# only to revision <= r0p2 of the Cortex A53 cpu.
ERRATA_A53_826319	?=0

# Flag to apply erratum 836870 workaround during reset. This erratum applies
# only to revision <= r0p3 of the Cortex A53 cpu. From r0p4 and onwards, this
# erratum workaround is enabled by default in hardware.
ERRATA_A53_836870	?=0

# Flag to apply errata 855873 during reset. This errata applies to all
# revisions of the Cortex A53 CPU, but this firmware workaround only works
# for revisions r0p3 and higher. Earlier revisions are taken care
# of by the rich OS.
ERRATA_A53_855873	?=0

# Flag to apply erratum 806969 workaround during reset. This erratum applies
# only to revision r0p0 of the Cortex A57 cpu.
ERRATA_A57_806969	?=0

# Flag to apply erratum 813419 workaround during reset. This erratum applies
# only to revision r0p0 of the Cortex A57 cpu.
ERRATA_A57_813419	?=0

# Flag to apply erratum 813420  workaround during reset. This erratum applies
# only to revision r0p0 of the Cortex A57 cpu.
ERRATA_A57_813420	?=0

# Flag to apply erratum 826974 workaround during reset. This erratum applies
# only to revision <= r1p1 of the Cortex A57 cpu.
ERRATA_A57_826974	?=0

# Flag to apply erratum 826977 workaround during reset. This erratum applies
# only to revision <= r1p1 of the Cortex A57 cpu.
ERRATA_A57_826977	?=0

# Flag to apply erratum 828024 workaround during reset. This erratum applies
# only to revision <= r1p1 of the Cortex A57 cpu.
ERRATA_A57_828024	?=0

# Flag to apply erratum 829520 workaround during reset. This erratum applies
# only to revision <= r1p2 of the Cortex A57 cpu.
ERRATA_A57_829520	?=0

# Flag to apply erratum 833471 workaround during reset. This erratum applies
# only to revision <= r1p2 of the Cortex A57 cpu.
ERRATA_A57_833471	?=0

# Flag to apply erratum 855972 workaround during reset. This erratum applies
# only to revision <= r1p3 of the Cortex A57 cpu.
ERRATA_A57_859972	?=0

# Process ERRATA_A53_826319 flag
$(eval $(call assert_boolean,ERRATA_A53_826319))
$(eval $(call add_define,ERRATA_A53_826319))

# Process ERRATA_A53_836870 flag
$(eval $(call assert_boolean,ERRATA_A53_836870))
$(eval $(call add_define,ERRATA_A53_836870))

# Process ERRATA_A53_855873 flag
$(eval $(call assert_boolean,ERRATA_A53_855873))
$(eval $(call add_define,ERRATA_A53_855873))

# Process ERRATA_A57_806969 flag
$(eval $(call assert_boolean,ERRATA_A57_806969))
$(eval $(call add_define,ERRATA_A57_806969))

# Process ERRATA_A57_813419 flag
$(eval $(call assert_boolean,ERRATA_A57_813419))
$(eval $(call add_define,ERRATA_A57_813419))

# Process ERRATA_A57_813420 flag
$(eval $(call assert_boolean,ERRATA_A57_813420))
$(eval $(call add_define,ERRATA_A57_813420))

# Process ERRATA_A57_826974 flag
$(eval $(call assert_boolean,ERRATA_A57_826974))
$(eval $(call add_define,ERRATA_A57_826974))

# Process ERRATA_A57_826977 flag
$(eval $(call assert_boolean,ERRATA_A57_826977))
$(eval $(call add_define,ERRATA_A57_826977))

# Process ERRATA_A57_828024 flag
$(eval $(call assert_boolean,ERRATA_A57_828024))
$(eval $(call add_define,ERRATA_A57_828024))

# Process ERRATA_A57_829520 flag
$(eval $(call assert_boolean,ERRATA_A57_829520))
$(eval $(call add_define,ERRATA_A57_829520))

# Process ERRATA_A57_833471 flag
$(eval $(call assert_boolean,ERRATA_A57_833471))
$(eval $(call add_define,ERRATA_A57_833471))

# Process ERRATA_A57_859972 flag
$(eval $(call assert_boolean,ERRATA_A57_859972))
$(eval $(call add_define,ERRATA_A57_859972))
