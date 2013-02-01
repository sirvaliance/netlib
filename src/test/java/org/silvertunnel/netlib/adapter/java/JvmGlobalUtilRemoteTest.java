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
package org.silvertunnel.netlib.adapter.java;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.silvertunnel.netlib.api.NetFactory;
import org.silvertunnel.netlib.api.NetLayer;
import org.silvertunnel.netlib.api.NetLayerIDs;
import org.silvertunnel.netlib.api.util.IpNetAddress;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;

/**
 * JUnit test cases to test NameServiceGlobalUtil and the NameService adapter.
 * 
 * Hint: Because of initialization issue, these test cases do not work in Eclipse -
 *       you have to start them (with ant) from command line! 
 * 
 * @author hapke
 */
@RunWith(JExample.class)
public class JvmGlobalUtilRemoteTest {
    private static final Logger log = Logger.getLogger(JvmGlobalUtilRemoteTest.class.getName());
    
    private static final String SOCKETTEST_HOSTNAME = "httptest.silvertunnel.org";
    private static final int SOCKETTEST_PORT = 80;

    private static final String DNSTEST_HOSTNAME = "dnstest.silvertunnel.org";
    private static final IpNetAddress DNSTEST_IP = new IpNetAddress("1.2.3.4");

    /** field to store a Throwable thrown in the static constructor to throw it later (in a test method) */
    private static Throwable throwableOfStaticInitializer;
    
    /**
     * Install services.
     * 
     * Do not use Junit's @org.junit.Before because this is too late.
     */
    static {
        log.info("static init");
        try {
            JvmGlobalUtil.init();
        } catch (Throwable t) {
            throwableOfStaticInitializer = t;
        }
    }
    
    /**
     * Check that the NopNet is really used after setup with JvmGlobalUtil.init().
     */
    @Test(timeout=5000)
    public void testAfterInit() throws Throwable {
        log.info("testAfterInit()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }

        // check functionality
        checkNopNet();
    }
    private void checkNopNet() {
        // test sockets
        try {
            // try to use Java standard way of TCP/IP communication
            new Socket(SOCKETTEST_HOSTNAME, SOCKETTEST_PORT).close();
            // we should not reach this code because socket creation should fail
            fail("Connection to "+SOCKETTEST_HOSTNAME+":"+SOCKETTEST_PORT+" was established (but not expected)");
            
        } catch (IOException e) {
            // this is expected
        }
        
        // test name service
        try {
            // try to use Java standard way of DNS resolution
            InetAddress[] result = InetAddress.getAllByName(DNSTEST_HOSTNAME);
            // we should not reach this code because name resolution should fail
            fail(DNSTEST_HOSTNAME+" could be resolved to "+Arrays.toString(result)+" (was not expected) - this probably means that the NetlibNameService was not used but the Internet instead");

        } catch (UnknownHostException e) {
            // this is expected
        }
    }
    
    /**
     * Check that the "DefaultNet" is used after JvmGlobalUtil.setDefaultNet();
     */
    @Test(timeout=20000)
    @Given("#testAfterInit")
    public void testDefaultNet() throws Throwable {
        log.info("testDefaultNet()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }
        
        // switch lower services and wait until ready
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TCPIP);
        JvmGlobalUtil.setNetLayerAndNetAddressNameService(netLayer, true);

        // check functionality
        checkDefaultNet();
    }
    private void checkDefaultNet() throws IOException {
        // test sockets
        {
            // try to use Java standard way of TCP/IP communication
            new Socket(SOCKETTEST_HOSTNAME, SOCKETTEST_PORT).close();
        }
        
        // test name service
        {
            // try to use Java standard way of DNS resolution
            InetAddress[] result = InetAddress.getAllByName(DNSTEST_HOSTNAME);
            assertEquals("wrong name resolution result", DNSTEST_IP, new IpNetAddress(result[0]));
        }
    }
    
    /**
     * Check using of TorNetLayer;
     */
    @Test(timeout=120000)
    @Given("#testAfterInit,#testDefaultNet")
    public void testTorNet() throws Throwable {
        log.info("testTorNet()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }
        
        // switch lower services and wait until ready
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR);
        JvmGlobalUtil.setNetLayerAndNetAddressNameService(netLayer, true);
        
        // check functionality
        checkTorNet();
    }
    private void checkTorNet() throws IOException {
        // test sockets
        {
            // try to use Java standard way of TCP/IP communication
            new Socket(SOCKETTEST_HOSTNAME, SOCKETTEST_PORT).close();
        }
        
        // test name service
        {
            // try to use Java standard way of DNS resolution
            InetAddress[] result = InetAddress.getAllByName(DNSTEST_HOSTNAME);
            assertEquals("wrong name resolution result", DNSTEST_IP, new IpNetAddress(result[0]));
        }
       
    }
    
    /**
     * Check that the "NotNet" is used after JvmGlobalUtil.setNopNet();
     */
    @Test(timeout=20000)
    @Given("#testAfterInit,#testTorNet")
    public void testNopNet() throws Throwable {
        log.info("testNopNet()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }
        
        // switch lower services and wait until ready
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.NOP);
        JvmGlobalUtil.setNetLayerAndNetAddressNameService(netLayer, true);
       
        // check functionality
        checkNopNet();
    }

    /**
     * Check using of TorNetLayer (special tests);
     */
    @Test(timeout=120000)
    @Given("#testAfterInit,#testNopNet")
    public void testTorNetAdvanced() throws Throwable {
        log.info("testTorNet2()");
        if (throwableOfStaticInitializer!=null) {
            throw throwableOfStaticInitializer;
        }
        
        // switch lower services and wait until ready
        NetLayer netLayer = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR);
        JvmGlobalUtil.setNetLayerAndNetAddressNameService(netLayer, true);
        
        // check functionality
        checkTorNetAdvanced();
    }
    private void checkTorNetAdvanced() throws IOException {
        // test sockets
        {
            // try to use Java standard way of TCP/IP communication
            Socket s = new Socket(SOCKETTEST_HOSTNAME, SOCKETTEST_PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            OutputStream os = s.getOutputStream();
            PrintStream out = new PrintStream(new DataOutputStream(os));
            
            // send message - without explicit flush! 
            out.print("GET / HTTP/1.");
            out.write('0');
            out.println("\n");
            
            // wait for server response
            String firstLine = in.readLine();
            assertEquals("wrong first line of response", "HTTP/1.1 200 OK", firstLine);
        }
    }
}
