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

import java.util.Collection;

import jdepend.framework.JDepend;
import jdepend.framework.JavaPackage;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

/**
 * JUnit test to to enforce dependency rules.
 * 
 * More examples: http://clarkware.com/software/JDepend.html#junit
 * 
 * @author hapke
 */
public class DependencyLocalTest {
    private static JDepend jdepend;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        jdepend = new JDepend();
        jdepend.addDirectory("build/classes");
    }

    /**
     * Tests that a package dependency cycle does not 
     * exist for any of the analyzed packages.
     */
    @Test(timeout=20000)
    public void testDependencyCycles_allPackages() {
        Collection<?> packages = jdepend.analyze();
        assertEquals("Cycles exist, for details run: \"ant clean build build-test jdepend\", packages="+packages, false, jdepend.containsCycles());
    }

    /**
     * Tests that a single package
     * does not contain any package dependency cycles.
     */
    @Ignore("test of a single packge is not needed because of testDependencyCycles_allPackages()")
    @Test(timeout=10000)
    public void testDependencyCycles_org_silvertunnel_netlib_layer_tor_api() {
        checkDependencyCycles("org.silvertunnel.netlib.layer.tor.api");
        checkDependencyCycles("org.silvertunnel.netlib.layer.tor.directory");
    }

    
    ///////////////////////////////////////////////////////
    // helper methods
    ///////////////////////////////////////////////////////
    
    /**
     * Tests that a single package
     * does not contain any package dependency cycles.
     * 
     * @param packageName
     */
    private void checkDependencyCycles(String packageName) {
        jdepend.analyze();
        JavaPackage p = jdepend.getPackage(packageName);
        assertEquals("Cycle exists: " + p.getName(), false, p.containsCycle());
    }
}
