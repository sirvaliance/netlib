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

import org.silvertunnel.netlib.layer.tor.circuit.CellRelayData;

/**
 * 
 * @author Lexi Pimenidis
 * @author Andriy Panchenko
 */
class TCPStreamThreadJava2TorThread extends Thread {
    private static final Logger log = Logger.getLogger(TCPStreamThreadJava2TorThread.class.getName());
    
    private TCPStream stream;
    /** read from this, and forward to tor */
    private PipedOutputStream sout; // 
    /** private end of this pipe */
    private PipedInputStream fromjava; // 
    /** as stop() is depreciated we use this toggle variable */
    private boolean stopped; 
    
    TCPStreamThreadJava2TorThread(TCPStream stream) {
        this.stream = stream;
        try {
            sout = new PipedOutputStream();
            fromjava = new PipedInputStream(sout);
        } catch (IOException e) {
            log.severe("TCPStreamThreadJava2Tor: caught IOException " + e.getMessage());
        }
        this.start();
    }
    
    public void close() {
        this.stopped = true;
        this.interrupt();
    }

    public void run() {
        while (!stream.isClosed() && !this.stopped) {
            try {
                int readBytes = fromjava.available();
                while (readBytes > 0 && !this.stopped) {
                    log.finer("TCPStreamThreadJava2Tor.run(): read " + readBytes + " bytes from application");
                    CellRelayData cell = new CellRelayData(stream);
                    cell.setLength(readBytes);
                    if (cell.getLength() > cell.getData().length) {
                        cell.setLength(cell.getData().length);
                    }
                    int b0 = fromjava.read(cell.getData(), 0, cell.getLength());
                    readBytes -= b0;
                    if (b0 < cell.getLength()) {
                        log.warning("TCPStreamThreadJava2Tor.run(): read " + b0 + " bytes where " + cell.getLength() + " were advertised");
                        cell.setLength(b0);
                    }

                    if (cell.getLength() > 0) {
                        stream.sendCell(cell);
                    }
                }
                Thread.yield();

            } catch (IOException e) {
                log.warning("TCPStreamThreadJava2Tor.run(): caught IOException " + e.getMessage());
            }
        }
    }
}
