#!/usr/bin/env bash
TASKDIR="st406386"
mkdir -p $TASKDIR
cp err.c err.h testhttp_raw.c Makefile $TASKDIR
cp testhttp.py "${TASKDIR}/testhttp"
tar czf "${TASKDIR}.tgz" "./${TASKDIR}"