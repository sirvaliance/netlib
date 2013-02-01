/*
 * silvertunnel.org Netlib - Java library to easily access anonymity networks
 * Copyright (c) 2009-2012 silvertunnel.org
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

package org.silvertunnel.netlib;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

import org.junit.Test;
import org.silvertunnel.netlib.adapter.url.NetlibURLStreamHandlerFactory;
import org.silvertunnel.netlib.adapter.url.URLGlobalUtil;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.util.TcpipNetAddress;
import org.silvertunnel.netlib.util.HttpUtil;

/**
 * This class summarizes some code fragments to demonstrate the usage of
 * HTTP APIs with silvertunnel.org Netlib.
 * 
 * This class is directly visible from some Wiki pages
 * and part of the silvertunnel.org Netlib documentation. The code fragments
 * are collected here instead and not in the Wiki to ensure that they are
 * always valid/correct and compile against the current version of the API.
 * (The author saw wrong/non compilable examples in other
 *  projects documentation too often - therefore we document it here)  
 * 
 * @author hapke
 */
public class NetlibHttpUsageExamplesRemoteTest {
    /**
     * Example: HTTP request using the very simple HttpUtil to load URL
     * http://httptest.silvertunnel.org/httptest/bigtest.jsp?id=example
     * 
     * More documentation:
     * http://sourceforge.net/apps/trac/silvertunnel/wiki/NetlibHttpUtil
     */
    @Test
    public void simple_HTTP_GET_request_with_HttpUtil() {
        try {
            // classic:   TcpipNetLayer with NetLayerIDs.TCPIP (--> HTTP over plain TCP/IP)
            // anonymous: TorNetLayer with NetLayerIDs.TOR (--> HTTP over TCP/IP over Tor network)
            //NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR); 
            NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP); 

            // wait until TOR is ready (optional) - this is only relevant for anonymous communication:
            lowerNetLayer.waitUntilReady();

            // prepare parameters (http default port: 80)
            TcpipNetAddress httpServerNetAddress = new TcpipNetAddress("httptest.silvertunnel.org", 80);
            String pathOnHttpServer = "/httptest/bigtest.jsp?id=example";
            long timeoutInMs = 5000;

            // do the HTTP request and wait for the response
            byte[] responseBody = HttpUtil.getInstance().get(lowerNetLayer, httpServerNetAddress, pathOnHttpServer, timeoutInMs);

            // print out the response
            System.out.println(new String(responseBody));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Example: HTTP request using Adapter URL to load
     * http://httptest.silvertunnel.org/httptest/bigtest.jsp?id=example2
     * 
     * This example does not change the global settings of java.net.URL
     * and is preferred over the next example
     * (execute_HTTP_GET_with_Adapter_URL_with_global_reconfiguration_of_class_URL).
     * 
     * More documentation:
     * http://sourceforge.net/apps/trac/silvertunnel/wiki/NetlibHttpUtil
     */
    @Test
    public void execute_HTTP_GET_with_Adapter_URL() {
        try {
            // classic:   TcpipNetLayer with NetLayerIDs.TCPIP (--> HTTP over plain TCP/IP)
            // anonymous: TorNetLayer with NetLayerIDs.TOR (--> HTTP over TCP/IP over Tor network)
            //NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP); 
            NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR); 

            // wait until TOR is ready (optional) - this is only relevant for anonymous communication:
            lowerNetLayer.waitUntilReady();

            // prepare URL handling on top of the lowerNetLayer
            NetlibURLStreamHandlerFactory factory = new NetlibURLStreamHandlerFactory(false);
            // the following method could be called multiple times
            // to change layer used by the factory over the time:
            factory.setNetLayerForHttpHttpsFtp(lowerNetLayer);

            // create the suitable URL object
            String urlStr = "http://httptest.silvertunnel.org/httptest/bigtest.jsp?id=example2";
            URLStreamHandler handler = factory.createURLStreamHandler("http");
            URL context = null;
            URL url = new URL(context, urlStr, handler);



            ///////////////////////////////////////////////
            // the rest of this method is as for every java.net.URL object,
            // read JDK docs to find out alternative ways:
            ///////////////////////////////////////////////
            
            // send request without POSTing data
            URLConnection urlConnection = url.openConnection();
            urlConnection.setDoInput(true); 
            urlConnection.setDoOutput(false); 
            urlConnection.connect();

            // receive and print the response
            BufferedReader response = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String line;
            while ((line=response.readLine())!=null) {
                System.out.println(line);
            }
            response.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
        System.out.println("************************************");
    }
    public static void main(String[] args) {
        new NetlibHttpUsageExamplesRemoteTest().execute_HTTP_GET_with_Adapter_URL();
    }
    
    
    /**
     * Example: HTTP request using Adapter URL to load
     * http://httptest.silvertunnel.org/httptest/bigtest.jsp?id=example3
     * 
     * This example changes the global settings of java.net.URL
     * and can have side effects to code in the same JVM. The way shown here
     * should only be used if necessary. Otherwise, the previous example
     * (execute_HTTP_GET_with_Adapter_URL_with_global_reconfiguration_of_class_URL)
     * if preferred.
     * 
     * More documentation:
     * http://sourceforge.net/apps/trac/silvertunnel/wiki/NetlibHttpUtil
     */
    // to to influence other tests in the same JVM: do not execute @Test
    public void execute_HTTP_GET_with_Adapter_URL_with_global_reconfiguration_of_class_URL() {
        try {
            // classic:   TcpipNetLayer with NetLayerIDs.TCPIP (--> HTTP over plain TCP/IP)
            // anonymous: TorNetLayer with NetLayerIDs.TOR (--> HTTP over TCP/IP over Tor network)
            //NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR); 
            NetLayer lowerNetLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP); 

            // wait until TOR is ready (optional) - this is only relevant for anonymous communication:
            lowerNetLayer.waitUntilReady();

            // redirect URL handling (JVM global)
            URLGlobalUtil.initURLStreamHandlerFactory();
            // the following method could be called multiple times
            // to change layer used by the global factory over the time:
            URLGlobalUtil.setNetLayerUsedByURLStreamHandlerFactory(lowerNetLayer);

            // create a URL object
            String urlStr = "http://httptest.silvertunnel.org/httptest/bigtest.jsp?id=example3";
            URL url = new URL(urlStr);



            ///////////////////////////////////////////////
            // the rest of this method is as for every java.net.URL object,
            // read JDK docs to find out alternative ways:
            ///////////////////////////////////////////////
            
            // send request without POSTing data
            URLConnection urlConnection = url.openConnection();
            urlConnection.setDoInput(true); 
            urlConnection.setDoOutput(false); 
            urlConnection.connect();

            // receive and print the response
            BufferedReader response = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String line;
            while ((line=response.readLine())!=null) {
                System.out.println(line);
            }
            response.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
