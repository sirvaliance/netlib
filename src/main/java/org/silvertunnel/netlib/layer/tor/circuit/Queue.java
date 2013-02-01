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
import java.util.Vector;
import java.util.logging.Logger;

import org.silvertunnel.netlib.layer.tor.util.TorException;
import org.silvertunnel.netlib.layer.tor.util.TorNoAnswerException;

/**
 * a helper class for queueing data (FIFO)
 * 
 * @author Lexi Pimenidis
 */
public class Queue {
    private static final Logger log = Logger.getLogger(Queue.class.getName());
    
    private static final int WAIT = 100;

    private volatile boolean closed = false;
    private volatile boolean addClosed = false;
    /** timeout internally represented in ms */
    private int timeoutMs = 1000; 
    private Vector<Cell> queue = new Vector<Cell>();
    private Vector<QueueHandler> handler = new Vector<QueueHandler>();

    /**
     * init class
     * 
     * @param timeoutS
     *            queue timeout in seconds
     */
    public Queue(int timeoutS) {
        this.timeoutMs = timeoutS * 1000;
    }

    public Queue() {
        this(1000);
    }

    public synchronized void addHandler(QueueHandler qh) {
        handler.add(qh);
    }

    public synchronized boolean removeHandler(QueueHandler qh) {
        return handler.remove(qh);
    }

    /** add a cell to the queue */
    public synchronized void add(Cell cell) {
        if (addClosed) {
            return;
        }
        /* first check if there are handlers installed */
        try {
            for(QueueHandler qh : handler) {
                try {
                    if (qh.handleCell(cell)) {
                        return;
                    }
                }
                catch(TorException te) { /* die silently */}
            }
        }
        catch(ClassCastException e) {}

        // otherwise add to queue
        queue.add(cell);

        this.notify();
    }

    /**
     * close the queue and remove all pending messages
     */
    public synchronized void close() {
        addClosed = true;
        closed = true;

        for (QueueHandler qh : handler) {
            qh.close();
        }
        
        queue.clear();
        this.notify();
    }

    /**
     * prohibit further writing to the queue
     */
    public synchronized void closeAdd() {
        addClosed = true;
        this.notify();
    }

    /** determines wether the queue is empty */
    boolean isEmpty() {
        if (closed) {
            return true;
        }
        return queue.size() == 0;
    }

    public Cell get() {
        return get(timeoutMs);
    }

    /**
     * get the first element from out of the class. Behaviour
     * 
     * @param timeout
     *            determines what will happen, if no data is in queue.
     * @return a Cell or null
     */
    public synchronized Cell get(int timeout) {

        boolean forever = false;
        if (timeout == -1)
            forever = true;

        int retries = timeout / WAIT;
        do {

            if (closed) {
                return null;
            }

            if (queue.size() > 0) {
                Cell cell = queue.get(0);
                queue.remove(0);
                return cell;
            } else if (addClosed) {
                closed = true;
                return null;
            }

            try {
                // wait for data
                wait(WAIT);
            } catch (InterruptedException e) {
            }
            --retries;
        } while (forever || (retries > 0) || (queue.size() > 0));

        return null;
    }

    /**
     * interface to receive a cell that is not a relay-cell
     */
    public Cell receiveCell(int type) throws IOException, TorException, TorNoAnswerException {
        Cell cell = get();
        if (cell == null) {
            throw new TorNoAnswerException("Queue.receiveCell: conection closed or no answer after " + this.timeoutMs / 1000 + " s", this.timeoutMs / 1000);
        }
        if (cell.getCommand() != type) {
            throw new TorException("Queue.receiveCell: expected cell of type "
                    + Cell.type(type) + " received type " + cell.type());
        }
        // if (cell.command == Cell.CELL_RELAY)
        // Tor.log.logCell(Logger.WARNING,"used from interface for receiving a
        // cell");
        return cell;
    }

    /**
     * interface to receive a relay-cell
     */
    public CellRelay receiveRelayCell(int type) throws IOException, TorException, TorNoAnswerException {
        CellRelay relay = (CellRelay) receiveCell(Cell.CELL_RELAY);
        if (relay.getRelayCommand() != type) {
            
            if ((relay.getRelayCommand() == CellRelay.RELAY_END) && (relay.getData() != null)) {
                throw new TorException(
                        "Queue.receiveRelayCell: expected relay-cell of type "
                                + CellRelay.relayCommand(type)
                                + ", received END-CELL for reason: "
                                + relay.reasonForClosing());

            } else {
                throw new TorException(
                        "Queue.receiveRelayCell: expected relay-cell of type "
                                + CellRelay.relayCommand(type)
                                + " received type " + relay.relayCommand());
            }
        }
        return relay;
    }

    ///////////////////////////////////////////////////////
    // getters and setters
    ///////////////////////////////////////////////////////
    
    public boolean isClosed() {
        return closed;
    }
    
    public int getTimeoutMs() {
        return timeoutMs;
    }

    public void setTimeoutMs(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }
    
}
