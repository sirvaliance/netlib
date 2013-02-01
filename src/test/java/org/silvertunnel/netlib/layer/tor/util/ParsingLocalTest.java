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

package org.silvertunnel.netlib.layer.tor.util;

import static org.junit.Assert.assertEquals;

import java.util.Date;
import java.util.logging.Logger;

import org.junit.Test;

/**
 * Test class Parsing.
 * 
 * @author hapke
 */
public class ParsingLocalTest {
    private static final Logger log = Logger.getLogger(ParsingLocalTest.class.getName());

    @Test
    public void testParseTimestampLine() {
        String startKeyWord = "publication-time";
        String documentToSearchIn = "publication-time 2010-03-09 13:41:53";
        Date result = Parsing.parseTimestampLine(startKeyWord, documentToSearchIn);
        String resultString = Util.formatUtcTimestamp(result);
        assertEquals("wrong parsed timestamp", "2010-03-09 13:41:53", resultString);
    }
}
