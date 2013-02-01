#!/bin/sh
# silvertunnel.org Netlib - Java library to easily access anonymity networks
# Copyright (c) 2009-2012 silvertunnel.org

# define classpath
CLASSES=build/classes
LIBDIR=lib/main
LIBS=$LIBDIR/bcprov-jdk15-145.jar:$LIBDIR/jdom.jar:$LIBDIR/silvertunnel.org_netlib.jar

# define optional opts to enable Java remote debugging on port 8000
#OPTS="-Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n"

# run program
echo java $OPTS -cp $CLASSES:$LIBS org.silvertunnel.netlib.tool.CheckNetConnectivity
java $OPTS -cp $CLASSES:$LIBS org.silvertunnel.netlib.tool.CheckNetConnectivity

