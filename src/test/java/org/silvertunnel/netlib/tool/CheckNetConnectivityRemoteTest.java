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

package org.silvertunnel.netlib.tool;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * This test case executes the checks of CheckNetConnectivity:
 * Execution of these checks during automatic test execution could provide additional information.
 * 
 * @author hapke
 */
public class CheckNetConnectivityRemoteTest {
    @Test(timeout=5000)
    public void testExecuteCheck() throws Exception {
        boolean result = CheckNetConnectivity.executeCheck(true);
        assertEquals("wrong result of executeCheck()", true, result);
    }
}
