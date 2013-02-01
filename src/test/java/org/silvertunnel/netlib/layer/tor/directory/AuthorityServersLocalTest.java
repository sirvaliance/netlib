/*
 * silvertunnel.org Netlib - Java library to easily access anonymity networks
 * Copyright (c) 2009-2013 silvertunnel.org
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
package org.silvertunnel.netlib.layer.tor.directory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Logger;

import org.junit.Test;
import org.silvertunnel.netlib.layer.tor.api.Fingerprint;
import org.silvertunnel.netlib.layer.tor.common.TorConfig;
import org.silvertunnel.netlib.layer.tor.directory.AuthorityServers;
import org.silvertunnel.netlib.layer.tor.directory.FingerprintImpl;
import org.silvertunnel.netlib.layer.tor.util.Encoding;


/**
 * Test of AuthorityServer.
 * 
 * @author hapke
 */
public class AuthorityServersLocalTest {
    private static final Logger log = Logger.getLogger(AuthorityServersLocalTest.class.getName());
    
    /**
     * Test AuthorityServers.getAuthorityIpAndPorts().
     * 
     * @throws Exception
     */
    @Test
    public void testGetAuthorityIpAndPorts() throws Exception {
        // action
        Collection<String> all = AuthorityServers.getAuthorityIpAndPorts();
        log.info("AuthorityServers.getAuthorityIpAndPorts().size()="+all.size());
        
        // check size
        assertEquals("wrong size", 10, all.size());

        // check data
        String example1 = "193.23.244.244:80";
        assertTrue("does not contain "+example1, all.contains(example1));
        String example2 = "171.25.193.9:443";
        assertTrue("does not contain "+example2, all.contains(example2));
    }
    
    
    /**
     * Test AuthorityServers.getAuthorityDirIdentityKeyDigests().
     * 
     * @throws Exception
     */
    @Test
    public void testGetAuthorizedAuthorityKeyIdentityKeys() throws Exception {
        // action
        Collection<Fingerprint> all = AuthorityServers.getAuthorityDirIdentityKeyDigests();
        log.info("AuthorityServers.getAuthorityDirIdentityKeyDigests().size()="+all.size());
        
        // check result
        String example1 = "585769C78764D58426B8B52B6651A5A71137189A";
        assertTrue("does not contain "+example1, all.contains(new FingerprintImpl(Encoding.parseHex(example1))));
        String example2 = "D586D18309DED4CD6D57C18FDB97EFA96D330566";
        assertTrue("does not contain "+example2, all.contains(new FingerprintImpl(Encoding.parseHex(example2))));
    }
    
    /**
     * Test AuthorityServers.getAuthorityRouters().
     * 
     * @throws Exception
     */
    @Test
    public void testGetAuthorityRouters() throws Exception {
        // action
        Collection<RouterImpl> all = AuthorityServers.getAuthorityRouters();
        
        // check size
        assertEquals("wrong size", 10, all.size());
        
        // check the 1st element
        Iterator<RouterImpl> iter = all.iterator();
        RouterImpl r = iter.next();
        assertEquals("wrong 1st element: wrong nickname", "moria1", r.getNickname());
        assertEquals("wrong 1st element: wrong address", "128.31.0.39", r.getAddress().getHostAddress());
        assertEquals("wrong 1st element: wrong dirPort", 9131, r.getDirPort());
        assertEquals("wrong 1st element: wrong fingerprint", new FingerprintImpl(Encoding.parseHex("9695DFC35FFEB861329B9F1AB04C46397020CE31")), r.getFingerprint());
        
        // check the 3rd element
        r = iter.next();
        r = iter.next();
        assertEquals("wrong 3rd element: wrong nickname", "dizum", r.getNickname());
        assertEquals("wrong 3rd element: wrong address", "194.109.206.212", r.getAddress().getHostAddress());
        assertEquals("wrong 3rd element: wrong dirPort", 80, r.getDirPort());
        assertEquals("wrong 3rd element: wrong fingerprint", new FingerprintImpl(Encoding.parseHex("7EA6EAD6FD83083C538F44038BBFA077587DD755")), r.getFingerprint());
    }
}
