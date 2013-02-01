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
package org.silvertunnel.netlib.layer.tor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.logging.Logger;

import org.junit.Test;
import org.silvertunnel.netlib.util.FileUtil;


/**
 * Test that reading system properties in TorConfic static constructor works.
 * 
 * These tests are not executed by default.
 * 
 * @author hapke
 */
public class TorNetLayerUtilLocalTest {
    private static final Logger log = Logger.getLogger(TorNetLayerUtilLocalTest.class.getName());

    private static final String TEMPDIR = System.getProperty("java.io.tmpdir");
    private static final String TEST_SUB_DIR_NAME = "testHiddenServiceDir";
    
    private static TorNetLayerUtil torNetLayerUtil = TorNetLayerUtil.getInstance();
    private static FileUtil fileUtil = FileUtil.getInstance();

    public static final String EXAMPLE_PRIVATE_KEY_PEM_PATH = "/org/silvertunnel/netlib/layer/tor/util/example-private-key-PEM.txt";
    public static final String EXAMPLE_ONION_DOMAIN_DERIVED_FROM_PRIVATE_KEY = "4xuwatxuqzfnqjuz";

    @Test(timeout=5000)
    public void testCreationOfNewHiddenSericePrivateNetAddresses() throws Exception {
        // 1st creation
        TorHiddenServicePrivateNetAddress netAddress1 = torNetLayerUtil.createNewTorHiddenServicePrivateNetAddress();
        log.info("new hidden service netAddress1="+netAddress1);
        assertNotNull("invalid netAddress1=null", netAddress1);
        log.finer("new hidden service netAddress1.getPrivateKey()="+netAddress1.getPrivateKey());
        
        // 2nd creation
        TorHiddenServicePrivateNetAddress netAddress2 = torNetLayerUtil.createNewTorHiddenServicePrivateNetAddress();
        log.info("new hidden service netAddress2="+netAddress2);
        assertNotNull("invalid netAddress2=null", netAddress2);
        log.finer("new hidden service netAddress2.getPrivateKey()="+netAddress1.getPrivateKey());

        // check that both hidden services are different
        assertFalse("new netAddress1=new netAddress2", netAddress1.equals(netAddress2));
    }

    @Test(timeout=5000)
    public void testParsingTorsOriginalHiddenSericePrivateNetAddressInfo() throws Exception {
        // read the Strings
        String originalTorPrivateKeyPEMStr = fileUtil.readFileFromClasspath(EXAMPLE_PRIVATE_KEY_PEM_PATH);
        log.info("originalTorPrivateKeyPEMStr="+originalTorPrivateKeyPEMStr);
        String originalTorHostnameStr = EXAMPLE_ONION_DOMAIN_DERIVED_FROM_PRIVATE_KEY+".onion";
        
        // parse and check
        final boolean checkHostname = true;
        TorHiddenServicePrivateNetAddress netAddress =
            torNetLayerUtil.parseTorHiddenServicePrivateNetAddressFromStrings(originalTorPrivateKeyPEMStr, originalTorHostnameStr, checkHostname);
        
        // show result
        log.info("netAddress="+netAddress);
        log.finer("netAddress.getPrivateKey()="+netAddress.getPrivateKey());
    }
    
    @Test(timeout=5000)
    public void testWritingAndReadingHiddenSericePrivateNetAddressInfo() throws Exception {
        // create new NetAddress
        TorHiddenServicePrivateNetAddress netAddressOriginal = torNetLayerUtil.createNewTorHiddenServicePrivateNetAddress();
        log.info("new hidden service netAddressOriginal="+netAddressOriginal);
        log.finer("new hidden service netAddressOriginal="+netAddressOriginal.toStringDetails());

        // prepare directory
        File directory = new File(TEMPDIR, TEST_SUB_DIR_NAME); 
        directory.mkdir();

        // write to directory
        torNetLayerUtil.writeTorHiddenServicePrivateNetAddressToFiles(directory, netAddressOriginal);
        
        // read from directory
        final boolean checkHostname = true;
        TorHiddenServicePrivateNetAddress netAddressRead = torNetLayerUtil.readTorHiddenServicePrivateNetAddressFromFiles(directory, checkHostname);
        log.info("new hidden service netAddressRead="+netAddressRead);
        log.finer("new hidden service netAddressRead="+netAddressRead.toStringDetails());
        
        // check result
        assertEquals("TorHiddenServicePrivateNetAddress changed after writing and reading", netAddressOriginal, netAddressRead);
    }
}
