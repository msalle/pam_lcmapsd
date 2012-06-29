# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
#     Mischa Sall\'e <msalle@nikhef.nl>
#

AM_CPPFLAGS = -DPAM_LCMAPSD_CONF=\"@CONFIG_FILE@\"
AM_CFLAGS = \
    -Wall \
    -Wuninitialized -Wbad-function-cast -Wcast-align -Wcast-qual \
    -Wmissing-prototypes -Wpointer-arith -Wredundant-decls \
    -Wshadow -Wstrict-prototypes -Wpointer-arith -Wno-long-long -Wundef

EXTRA_DIST = LICENSE \
	     bootstrap

# Library
securelibdir = @SECUREDIR@

securelib_LTLIBRARIES = pam_lcmapsd.la
pam_lcmapsd_la_LDFLAGS = -module -avoid-version
pam_lcmapsd_la_SOURCES = \
    pam_lcmapsd.h pam_lcmapsd_opts.c \
    lcmapsd_client.c lcmapsd_client.h \
    pam_lcmapsd.c

# Test program
sbin_PROGRAMS = lcmapsd_test_client
lcmapsd_test_client_CFLAGS = -DMAKE_A_OUT
lcmapsd_test_client_SOURCES = \
    pam_lcmapsd.h pam_lcmapsd_opts.c \
    lcmapsd_client.c lcmapsd_client.h \
    testclient.c
