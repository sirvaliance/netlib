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
package org.silvertunnel.netlib.layer.tor.circuit;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.util.TorException;

/**
 * convenient way to handle flow-control
 * 
 * @author Lexi
 */
public class QueueFlowControlHandler implements QueueHandler {
    private static final Logger log = Logger.getLogger(QueueFlowControlHandler.class.getName());

    private int counter;
    private int currLevel;
    private int startLevel;
    private int incLevel;
    private Circuit circuit;
    private Stream stream;
    private boolean circuitLevel;

    QueueFlowControlHandler(Circuit circuit, int startLevel, int incLevel) {
        this.circuit = circuit;
        this.counter = 0;
        this.startLevel = startLevel;
        this.currLevel = startLevel;
        this.incLevel = incLevel;
    }

    public QueueFlowControlHandler(Stream stream, int startLevel, int incLevel) {
        this.stream = stream;
        this.counter = 0;
        this.startLevel = startLevel;
        this.currLevel = startLevel;
        this.incLevel = incLevel;
    }

    private synchronized void count() {
        --currLevel;
        ++counter;
    }

    private synchronized void increase() {
        currLevel += incLevel;
    }

    /** return TRUE, if cell was handled */
    public boolean handleCell(Cell cell) throws TorException {
        count();
        // dropped below threshold - oh no!
        // better start sending SENDMEs...
        if (currLevel <= startLevel - incLevel) {
            try {
                if (circuit != null) {
                    // send to all routers in the circuit
                    if (log.isLoggable(Level.FINE)) {
                        log.fine("QueueFlowControlHandler.mainAction(): (" + counter + ") " + currLevel + "<" + startLevel + " sending SENDME for circuit " + circuit.toString());
                    }
                    for (int i = 0; i < circuit.getRouteEstablished(); ++i) {
                        circuit.sendCell(new CellRelaySendme(circuit, i));
                    }
                }

                if (stream != null) {
                    // send to end-point
                    if (log.isLoggable(Level.FINE)) {
                        log.fine("QueueFlowControlHandler.mainAction(): (" + counter + ") " + currLevel + "<" + startLevel + " sending SENDME for stream " + stream.toString());
                    }
                    stream.sendCell(new CellRelaySendme(stream));
                }

                increase();

            } catch (IOException e) {
                if (circuit != null) {
                    log.warning("QueueFlowControlHandler.mainAction(): error sending SENDME " + e.getMessage());
                }
                if (stream != null) {
                    log.warning("QueueFlowControlHandler.mainAction(): error sending SENDME "  + e.getMessage());
                }
            }
        }

        // always return FALSE to avoid swallowing cells
        return false;
    }

    /** close these things */
    public void close() {
    }
}
