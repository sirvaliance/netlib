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
package org.silvertunnel.netlib.layer.tor.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Register TorEventHandler and fire TorEvents.
 * 
 * @author hapke
 */
public class TorEventService {
    private static final Logger log = Logger.getLogger(TorEventService.class.getName());
    
    private Collection<TorEventHandler> eventHandlers = new ArrayList<TorEventHandler>();

    public void registerEventHandler(TorEventHandler eventHandler) {
        eventHandlers.add(eventHandler);
    }

    public boolean removeEventHandler(TorEventHandler eventHandler) {
        return eventHandlers.remove(eventHandler);
    }

    /**
     * Fire the event - in all registered handlers.
     * 
     * @param event
     */
    public void fireEvent(TorEvent event) {
        for (TorEventHandler eventHandler : eventHandlers) {
            try {
                eventHandler.fireEvent(event);
            } catch (Exception e) {
                log.log(Level.WARNING, "TorEventService.fireEvent()",  e);
            }
        }
    }
}
