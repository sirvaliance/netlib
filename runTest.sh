#!/bin/sh
#ant -Djava.util.logging.config.file=build/test-classes/logging.properties -Dtest.class=**/TorMemRemoteTest.class run-test 2>&1 | tee log
#ant -Djava.util.logging.config.file=build/test-classes/logging.properties -Dtest.class=**/JvmGlobalUtilRemoteTest.class run-test 2>&1 | tee log

# define classpath
CLASSES=build/classes:build/test-classes
LIBDIR=lib/main
LIBS=$LIBDIR/bcprov-jdk15-145.jar:$LIBDIR/jdom.jar:$LIBDIR/silvertunnel.org_netlib.jar

# define optional opts to enable Java remote debugging on port 8000
OPTS="-Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n -Djava.util.logging.config.file=build/test-classes/logging.properties"

# run program
echo java $OPTS -cp $CLASSES:$LIBS org.silvertunnel.netlib.T1RemoteTest 2>&1 | tee log
java $OPTS -cp $CLASSES:$LIBS org.silvertunnel.netlib.layer.tor.T1RemoteTest 2>&1 | tee log

