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
package org.silvertunnel.netlib.layer.tor.circuit;

import java.io.IOException;
import java.util.Date;

/**
 * Abstract kind of TCPStream.
 * 
 * @author hapke
 */
public interface Stream {
    /**
     * for internal usage
     * 
     * @param force
     *            if set to true, just destroy the object, without sending
     *            END-CELLs and stuff
     */
    public void close(boolean force);
    
    public void setId(int id);
    public int getId();
    public boolean isClosed();
    public Date getLastCellSentDate();
    public Circuit getCircuit();
    public void sendCell(Cell c) throws IOException;
    public Queue getQueue();
}
