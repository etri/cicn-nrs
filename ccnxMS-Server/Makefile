EXECUTABLES = ccnxReg_Server

all: ${EXECUTABLES}

INCLUDE_DIR_FLAGS=-I. -I/include
CCNX_LIB_FLAGS=-lccnx_api_portal -lccnx_api_notify -lccnx_transport_rta -lccnx_api_control -lccnx_common
PARC_LIB_FLAGS=-lparc -llongbow -llongbow-ansiterm
CFLAGS=${INCLUDE_DIR_FLAGS} ${LINK_DIR_FLAGS} ${CCNX_LIB_FLAGS} ${PARC_LIB_FLAGS} ${DEP_LIB_FLAGS}

CC=gcc -O2 -std=c99 -D _GNU_SOURCE

ccnxReg_Server: ccnxReg_Server.o ccnxNRS_Common.o ccnxPing_Stats.o
	${CC} ccnxReg_Server.o ccnxNRS_Common.o ccnxPing_Stats.o ${CFLAGS} -lmysqlclient -o ccnxReg_Server

ccnxReg_Server.o: ccnxReg_Server.c ccnxNRS_Common.h ccnxPing_Stats.h
	${CC} ${CFLAGS} -c ccnxReg_Server.c
ccnxNRS_Common.o: ccnxNRS_Common.c ccnxNRS_Common.h
	${CC} ${CFLAGS} -c ccnxNRS_Common.c

ccnxPing_Stats.o: ccnxPing_Stats.c ccnxPing_Stats.h
	${CC} ${CFLAGS} -c ccnxPing_Stats.c
clean:
	rm -rf ${EXECUTABLES} *.o

