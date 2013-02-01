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

package org.silvertunnel.netlib.api.impl;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.util.logging.Logger;

/**
 * InputStream wrapper needed by NetSocket2SocketImpl
 * to handle timeout (SO_TIMEOUT) correctly.
 */
public class SocketTimeoutInputStream extends FilterInputStream {
    private static final Logger log = Logger.getLogger(SocketTimeoutInputStream.class.getName());

    /** timeout of all potentially blocking methods */ 
    private long timeout;

    /** requests for the thread */
    volatile boolean closeRequestedByServiceUser;
    /** requests for the thread */
    volatile boolean waitingForClose;

    /** null if thread is terminated */
    private SocketTimeoutInputStreamThread thread;
    
    /** site ring buffer to store the data */
    final int BUFFER_SIZE = 4096;
    /** ring buffer to store the data */
    byte[] buffer = new byte[BUFFER_SIZE];
    /** index of the first unread byte in buffer */
    int bufferHead = 0;
    /** number of unread bytes in buffer */
    int bufferLen = 0;

    /** store pending exceptions (if any) */
    volatile IOException lastPendingIOException;
    
    /**
     * Creates a timeout wrapper for an input stream.
     * 
     * @param in         the underlying input stream
     * @param timeout    the number of milliseconds to block; 0=no timeout, -1=close the stream in the background
     */
    public SocketTimeoutInputStream(InputStream in, long timeout) {
        super(in);
        this.timeout = timeout;
        
        thread = new SocketTimeoutInputStreamThread(this, in);
        thread.start();
    }

    /**
     * Set a new timeout value.
     * 
     * @param timeout    the number of milliseconds to block; 0=no timeout, -1=close the stream in the background
     */
    public synchronized void setTimeout(long timeout) {
        this.timeout = timeout;
    }
 
    ///////////////////////////////////////////////////////
    // methods to cover the InputStream API methods
    ///////////////////////////////////////////////////////

    /**
     * @throws SocketTimeoutException    if the timeout expired
     * @throws IOException
     */
    @Override
    public void close() throws SocketTimeoutException, IOException {
        Thread oldThread;
        super.close();
        synchronized (this) {
            if (thread == null) {
                return;
            } 
            
            oldThread = thread;
            closeRequestedByServiceUser = true;
            thread.interrupt();
            throwLastPendingIOException();
        }
        if (timeout == -1) {
            return;
        }
        try {
            oldThread.join(timeout);
        } catch (InterruptedException e) {
            // not expected
            Thread.currentThread().interrupt();
        }
        synchronized (this) {
            throwLastPendingIOException();
            if (thread != null) {
                throw new SocketTimeoutException();
            }
        }
    }
    
    /**
     * @return the number of unread bytes in the buffer
     * @throws IOException
     */
    @Override
    public synchronized int available() throws IOException {
        if (bufferLen == 0) {
            throwLastPendingIOException();
        }
        return (bufferLen > 0) ? bufferLen : 0;
    }
    
    @Override
    public synchronized int read() throws IOException {
        final int ONE = 1;
        final byte[] buffer1 = new byte[ONE];
        
        int len = read(buffer1, 0, ONE);
        if (len<1) {
            // EOF
            return -1;
        } else {
            // one byte read
            return buffer1[0] & 255;
        }
    }
    
    @Override
    public synchronized int read(byte[] buf, int off, int len) throws IOException {
        if (!waitUntilBufferIsFilled()) {
            // EOF
            return -1;
        }
        int pos = off;
        if (len > bufferLen) {
            len = bufferLen;
        }
        while (len-- > 0) {
            buf[pos++] = buffer[bufferHead++];
            if (bufferHead == buffer.length) {
                bufferHead = 0;
            }
            bufferLen--;
        }
        notify();
        return pos - off;
    }

    @Override
    public synchronized long skip(long count) throws IOException {
        long amount = 0;
        try {
            do {
                if (!waitUntilBufferIsFilled()) {
                    // EOF
                    break;
                }
                int skip = (int) Math.min(count - amount, bufferLen);
                bufferHead = (bufferHead + skip) % buffer.length;
                bufferLen -= skip;
                amount += skip;
            } while (amount < count);
        } catch (SocketTimeoutException e) {
            e.bytesTransferred = (int) amount;
            throw e;
        }
        notify();
        return amount;
    }

    /**
     * Not supported.
     */
    @Override
    public boolean markSupported() {
        return false;
    }

    
    ///////////////////////////////////////////////////////
    // helper methods
    ///////////////////////////////////////////////////////

    /**
     * @return true if at least one byte is available, false if EOF has been reached
     * @throws IOException               a pending exception if available
     * @throws SocketTimeoutException    if EOF not reached but no bytes are available
     */
    private boolean waitUntilBufferIsFilled() throws IOException, SocketTimeoutException {
        if (bufferLen != 0) {
            // at least one byte is available 
            return true;
        }
        
        // try to read more bytes
        throwLastPendingIOException();
        if (waitingForClose) {
            return false;
        }
        notify();
        try {
            wait(timeout);
        } catch (InterruptedException e) {
            // unexpected
            Thread.currentThread().interrupt();
        }
        throwLastPendingIOException();
        if (bufferLen != 0) {
            // at least one byte is available now
            return true;
        }
        if (waitingForClose) {
            // EOF reached
            return false;
        }
        throw new SocketTimeoutException();
    }

    /**
     * @throws IOException if an exception is pending
     */
    private void throwLastPendingIOException() throws IOException {
        if (lastPendingIOException != null) {
            IOException e = lastPendingIOException;
            lastPendingIOException = null;
            throw e;
        }
    }
}
