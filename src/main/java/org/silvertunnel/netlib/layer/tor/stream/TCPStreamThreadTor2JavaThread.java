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
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.circuit.Cell;
import org.silvertunnel.netlib.layer.tor.circuit.CellRelay;

/**
 * this class contains a background thread that waits for incoming cells in a
 * TCPStream and makes them available to the Java-Application.
 * 
 * @author Lexi Pimenidis
 * @author Andriy Panchenko
 * @see TCPStreamThreadJava2TorThread
 */
class TCPStreamThreadTor2JavaThread extends Thread {
    private static final Logger log = Logger.getLogger(TCPStreamThreadTor2JavaThread.class.getName());
    
    private TCPStream stream;
    /** read from tor and output to this stream */
    private PipedInputStream sin;
    /** private end of this pipe */
    private PipedOutputStream fromtor; 
    /** as stop() is depreacated we use this toggle variable */
    private boolean stopped; 
    
    TCPStreamThreadTor2JavaThread(TCPStream stream) {
        this.stream = stream;
        try {
            sin = (PipedInputStream) new SafePipedInputStream();
            fromtor = new PipedOutputStream(sin);
        } catch (IOException e) {
            log.severe("TCPStreamThreadTor2Java: caught IOException " + e.getMessage());
        }
        this.start();
    }

    public void close() {
        this.stopped = true;
        this.interrupt();
    }
    
    public void run() {
        while (!stream.isClosed() && !this.stopped) {
            Cell cell = stream.queue.get();
            if (cell != null) {
                if (!cell.isTypeRelay()) {
                    log.severe("TCPStreamThreadTor2Java.run(): stream " + stream.getId() + " received NON-RELAY cell:\n" + cell.toString());
                } else {
                    CellRelay relay = (CellRelay) cell;
                    if (relay.isTypeData()) {
                        log.finer("TCPStreamThreadTor2Java.run(): stream " + stream.getId() + " received data");
                        try {
                            fromtor.write(relay.getData(), 0, relay.getLength());
                        } catch (IOException e) {
                            log.severe("TCPStreamThreadTor2Java.run(): caught IOException " + e.getMessage());
                        }
                    } else if (relay.isTypeEnd()) {
                        log.finer("TCPStreamThreadTor2Java.run(): stream " + stream.getId() + " is closed: " + relay.reasonForClosing());
                        stream.setClosedForReason( (int) (relay.getPayload()[0]) & 0xff);
                        stream.setClosed(true);
                        stream.close(true);
                    } else {
                        log.severe("TCPStreamThreadTor2Java.run(): stream " + stream.getId() + " received strange cell:\n" + relay.toString());
                    }
                }
            }
        }
    }
}
