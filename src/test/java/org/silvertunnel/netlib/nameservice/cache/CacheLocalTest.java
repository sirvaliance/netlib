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

package org.silvertunnel.netlib.nameservice.cache;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.junit.Before;
import org.junit.Test;

/**
 * Test of DefaultIpNetAddressNameService.
 * 
 * @author hapke
 */
public class CacheLocalTest {
    private static final Logger log = Logger.getLogger(CacheLocalTest.class.getName());
    
    /** Cache to Test */
    private Map<Integer,String> cache;
    
    private static final int TIME_TO_LIVE_SECONDS = 2;
    private static final int MAX_ELEMENTS = 3;
    
    @Before
    public void setUp() {
        cache = new Cache<Integer,String>(MAX_ELEMENTS, TIME_TO_LIVE_SECONDS);

        // some test cases would fail with simple HasHap:
        // cache = new HashMap<Integer,String>();
    }

    @Test
    public void testPutGetSizeClear() {
        // put
        assertEquals("invalid size (a)", 0, cache.size());
        cache.put(1, "eins");
        cache.put(22, "zwei");
        cache.put(333, "drei");
        
        // check get
        assertEquals("invalid size", 3, cache.size());
        assertEquals("invalid value", "zwei", cache.get(22));
        assertEquals("invalid value", "drei", cache.get(333));
        assertEquals("invalid value", "eins", cache.get(1));
        assertEquals("invalid size", 3, cache.size());
       
        // check with invalid key
        assertNull("found value with invalid key", cache.get(4444));
        assertEquals("invalid size", 3, cache.size());
        
        // check check
        cache.clear();
        assertEquals("invalid size (b)", 0, cache.size());
    }

    @Test
    public void testTimeToLive() throws Exception {
        // put
        assertEquals("invalid size (a)", 0, cache.size());
        cache.put(1, "eins");

        // check get
        assertEquals("invalid size (b)", 1, cache.size());
        assertEquals("invalid value", "eins", cache.get(1));
     
        // enforce timeout
        Thread.sleep((1000L*TIME_TO_LIVE_SECONDS)+100L);
        
        // check get
        assertEquals("invalid size (c)", 0, cache.size());
        assertNull("found value after live time", cache.get(1));
    }

    @Test
    public void testMaxElements() {
        // fill the cache
        for (int i=1; i<MAX_ELEMENTS+1000; i++) {
            cache.put(i, "myValue"+i);
            assertTrue("size()="+cache.size()+" too high", cache.size()<=MAX_ELEMENTS);
        }
        log.info("full cache="+cache);
        
        // check that there are MAX_ELEMENTS different entries in the cache
        assertEquals("invalid size", MAX_ELEMENTS, cache.size());
        Set<String> values = new HashSet<String>();
        for (Map.Entry<Integer,String> entry : cache.entrySet()) {
            // check that the value belongs to the key
            String expectedValue = "myValue"+entry.getKey();
            assertEquals("invalid value for key="+entry.getKey(), expectedValue, entry.getValue());
            values.add(entry.getValue());
        }
        assertEquals("invalid number of unique values="+values+" in the cache="+cache, MAX_ELEMENTS, values.size());
    }
}
