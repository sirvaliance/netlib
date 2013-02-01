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

import static org.junit.Assert.assertEquals;

import java.util.logging.Logger;

import org.junit.Test;

/**
 * JUnit test to test the JUnit execution environment:
 * each test case class should be executed in a separate JVM.
 * This will be enforced in ant task junit/batchtest
 * with fork="yes" and (default) forkmode="perTest". 
 *
 * The test scenario consists of two test case classes:
 * @see org.silvertunnel.netlib.JUnitForkMode1LocalTest
 * @see org.silvertunnel.netlib.JUnitForkMode2LocalTest
 * 
 * @author hapke
 */
public class JUnitForkMode1LocalTest {
    private static final Logger log = Logger.getLogger(JUnitForkMode1LocalTest.class.getName());
    
    /** global flag: this may not be set by any other test case class in the JVM that executes this test */
    public static volatile boolean alreadyExecuted = false;
    
    @Test
    public void testThatImRunningInMyOwnJVM() {
        log.info("run testThatImRunningInMyOwnJVM()");
        assertEquals("wrong value of variable \"alreadyExecuted\", i.e. test cases classes are NOT executed in separate JVM (but they should!)",
                false, JUnitForkMode1LocalTest.alreadyExecuted);
        JUnitForkMode1LocalTest.alreadyExecuted = true;
    }
}
