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
import org.junit.runner.RunWith;

import ch.unibe.jexample.Given;
import ch.unibe.jexample.JExample;

/**
 * JUnit test to test the JExample features.
 * 
 * http://stackoverflow.com/questions/512778/ordering-unit-tests-in-eclipses-junit-view
 * http://scg.unibe.ch/research/jexample
 * http://www.iam.unibe.ch/~akuhn/blog/2008/jexample-quickstart/
 * http://sourceforge.net/projects/jexample/
 * 
 * @author hapke
 */
@RunWith(JExample.class)
public class JExampleLocalTest {
    private static final Logger log = Logger.getLogger(JExampleLocalTest.class.getName());

    /** Hint: @BeforeClass is currently not working together with @RunWith(JExample.class) */
    private static int counter=1;
    
    /** should be executed as 1st test case */
    @Test
    public void testA() {
        log.info("I'm here: testA()/expected to be 1st test case");
        assertEquals("wrong order/counter", 1, counter++);
    }

    /** should be executed as 3rd test case */
    @Test
    @Given("#testC")
    public void testB() {
        log.info("I'm here: testB()/expected to be 3rd test case");
        assertEquals("wrong order/counter", 3, counter++);
    }

    /** should be executed as 2nd test case */
    @Test
    @Given("#testA")
    public void testC() {
        log.info("I'm here: testC()/expected to be 2nd test case");
        assertEquals("wrong order/counter", 2, counter++);
    }

    /** should be executed as 4th/last test case */
    @Test
    @Given("#testB")
    public void testD() {
        log.info("I'm here: testD()/expected to be 4th/last test case");
        assertEquals("wrong order/counter", 4, counter++);
    }
}
