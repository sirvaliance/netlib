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

package org.silvertunnel.netlib.layer.tor.stream;


import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.circuit.Cell;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelay;
import org.silvertunnel.netlib.layer.tor.circuit.QueueHandler;
import org.silvertunnel.netlib.layer.tor.util.TorException;


/**
 * used to be TCPStreamThreadTor2Java
 */
class QueueTor2JavaHandler implements QueueHandler {
    private static final Logger log = Logger.getLogger(QueueTor2JavaHandler.class.getName());
    
    private TCPStream stream;
    /** read from tor and output to this stream */
    private PipedInputStream sin;
    /** private end of this pipe */
    private PipedOutputStream fromtor; 
    /** as stop() is depreciated we use this toggle variable */
    private boolean stopped;

    QueueTor2JavaHandler(TCPStream stream) {
        this.stream = stream;
        try {
            sin = (PipedInputStream) new SafePipedInputStream();
            fromtor = new PipedOutputStream(sin);
        } catch (IOException e) {
            log.severe("QueueTor2JavaHandler: caught IOException " + e.getMessage());
        }
    }

    public void close() {
        this.stopped = true;
        /* leave data around, until no more referenced by someone else */
        //try{ sin.close(); } catch(Exception e) {}
        try{ fromtor.close();  } catch(Exception e) {}
    }

    /** return TRUE, if cell was handled */
    public boolean handleCell(Cell cell) 
        throws TorException
    {
        if(stream.isClosed() || this.stopped) return false;
        if (cell == null) return false;
        if (!cell.isTypeRelay()) return false;

        CellRelay relay = (CellRelay) cell;
        if (relay.isTypeData()) {
            log.finer("QueueTor2JavaHandler.handleCell(): stream " + stream.getId() + " received data");
            try {
                fromtor.write(relay.getData(), 0, relay.getLength());
            } catch (IOException e) {
                log.severe("QueueTor2JavaHandler.handleCell(): caught IOException "    + e.getMessage());
            }
            return true;
        } else if (relay.isTypeEnd()) {
            log.finer("QueueTor2JavaHandler.handleCell(): stream " + stream.getId() + " is closed: " + relay.reasonForClosing());
            stream.setClosedForReason( (int) (relay.getPayload()[0]) & 0xff);
            stream.setClosed(true);
            stream.close(true);
            this.stopped = true;
            return true;
        }
        return false;
    }
    
    public InputStream getInputStream() {
        return sin;
    }
}
