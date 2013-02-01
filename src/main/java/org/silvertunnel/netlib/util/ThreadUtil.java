/**
 * OnionCoffee - Anonymous Communication through TOR Network
 * Copyright (C) 2005-2007 RWTH Aachen University, Informatik IV
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */
package org.silvertunnel.netlib.util;

import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * This class contains methods to log running threads.
 * 
 * @author Lexi Pimenidis
 * @author Andriy Panchenko
 * @author Michael Koellejan
 * @author hapke
 */
public class ThreadUtil {
    private static final Logger log = Logger.getLogger(ThreadUtil.class.getName());

    /**
     * This method recursively visits (logs with INFO level) all threads.
     * 
     * @param log
     * @param logLevel
     */
    public static void logAllRunningThreads() {
        logAllRunningThreads(log, Level.INFO);
    }

    /**
     * This method recursively visits (logs) all threads.
     * 
     * @param log
     * @param logLevel
     */
    public static void logAllRunningThreads(Logger log, Level logLevel) {
        ThreadGroup root = Thread.currentThread().getThreadGroup().getParent();
        while (root.getParent() != null) {
            root = root.getParent();
        }

        // Visit each thread group
        logThreadGroup(log, logLevel, root, 0);
    }

    /**
     * This method recursively visits (log.info()) all thread groups under `group'.
     * 
     * @param log
     * @param logLevel
     */
    public static void logThreadGroup(Logger log, Level logLevel, ThreadGroup group, int level) {
        // Get threads in `group'
        int numThreads = group.activeCount();
        Thread[] threads = new Thread[numThreads * 2];
        numThreads = group.enumerate(threads, false);

        // Enumerate each thread in `group'
        for (int i = 0; i < numThreads; i++) {
            // Get thread/
            Thread thread = threads[i];
            log.log(logLevel, thread.toString());
        }

        // Get thread subgroups of `group'
        int numGroups = group.activeGroupCount();
        ThreadGroup[] groups = new ThreadGroup[numGroups * 2];
        numGroups = group.enumerate(groups, false);

        // Recursively visit each subgroup
        for (int i = 0; i < numGroups; i++) {
            logThreadGroup(log, logLevel, groups[i], level + 1);
        }
    }
}
