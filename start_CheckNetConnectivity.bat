@echo off
REM silvertunnel.org Netlib - Java library to easily access anonymity networks
REM Copyright (c) 2009-2012 silvertunnel.org

REM define classpath
set CLASSES=build\classes
set LIBDIR=lib\main
set LIBS=%LIBDIR%\bcprov-jdk15-145.jar;%LIBDIR%\jdom.jar;%LIBDIR%\silvertunnel.org_netlib.jar

REM define optional opts to enable Java remote debugging on port 8000
REM set OPTS=-Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=n

REM run program
echo java -cp %CLASSES%;%LIBS% org.silvertunnel.netlib.tool.NetProxy 127.0.0.1:1080 socks_over_tor_over_tls_over_tcpip
echo java %OPTS% -cp %CLASSES%;%LIBS% org.silvertunnel.netlib.tool.CheckNetConnectivity
java %OPTS% -cp %CLASSES%;%LIBS% org.silvertunnel.netlib.tool.CheckNetConnectivity
