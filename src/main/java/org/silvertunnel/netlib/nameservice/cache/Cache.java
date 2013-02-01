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

package org.silvertunnel.netlib.nameservice.cache;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class provides a very simple, general purpose cache implementation.
 * 
 * The idea is to be compatible with/a subset of JCache JSR 107
 * and to be compatible with java.util.Map.
 * 
 * @author hapke
 */
public class Cache<K,V> implements Map<K,V> {
    /** the stored elements */
    private Map<K,CacheEntry<K,V>> storage;
    
    /** configuration parameter */
    private int timeToLiveSeconds;
    /** configuration parameter */
    private int maxElements;
    
    /** constructor argument limit */
    private static final int MIN_MAX_ELEMENTS = 1;
    
 
    /**
     * Create a new cache instance.
     * 
     * @param timeToLiveSeconds    <0 means unlimited time to live, 0 means no caching
     * @param maxElements          >=1
     */
    public Cache(int maxElements, int timeToLiveSeconds) {
        if (timeToLiveSeconds<0) {
            timeToLiveSeconds = Integer.MAX_VALUE;
        }
        this.timeToLiveSeconds = timeToLiveSeconds;
        
        if (maxElements<MIN_MAX_ELEMENTS) {
            throw new IllegalArgumentException("invalid maxElements="+maxElements);
        }
        this.maxElements = maxElements;
        
        storage = new HashMap<K,CacheEntry<K,V>>(maxElements);
    }
    
    public synchronized void clear() {
        storage.clear();
    }

    public synchronized boolean containsKey(Object key) {
        V v = get(key);
        return v!=null;
    }

    public synchronized boolean containsValue(Object value) {
        return values().contains(value);
    }

    public synchronized Set<java.util.Map.Entry<K, V>> entrySet() {
        Set<java.util.Map.Entry<K, V>> entries = new HashSet<java.util.Map.Entry<K, V>>(storage.size());
        
        for (K key : storage.keySet()) {
            CacheEntry<K,V> cacheValue = storage.get(key);
            if (cacheValue!=null) {
                entries.add(cacheValue);
            }
        }

        return entries;
    }

    public synchronized V get(Object key) {
        if (timeToLiveSeconds==0) {
            // do not cache
            return null;
        }

        CacheEntry<K,V> value = storage.get(key);
        if (value==null) {
            // no entry found
            return null;
        } else if (value.isExpired()) {
            // expired entry found
            storage.remove(key);
            return null;
        } else {
            // valid entry found
            return value.getValue();
        }
    }

    public synchronized boolean isEmpty() {
        return storage.isEmpty();
    }

    public synchronized Set<K> keySet() {
        return storage.keySet();
    }

    public synchronized V put(K key, V value) {
        if (timeToLiveSeconds==0) {
            // do not cache
            return null;
        }
        
        ensureThatAtLeastOneMoreEntryCanBePutted();
        
        CacheEntry<K,V> valueNew = new CacheEntry<K,V>(key, value, timeToLiveSeconds);
        CacheEntry<K,V> valueOld = storage.put(key, valueNew);
        return (valueOld==null) ? null :valueOld.getValue();
    }

    public synchronized void putAll(Map<? extends K, ? extends V> m) {
        for (Map.Entry<? extends K, ? extends V> entry : m.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    public synchronized V remove(Object key) {
        CacheEntry<K,V> v = storage.remove(key);
        return (v==null) ? null : v.getValue();
    }

    public synchronized int size() {
        removeExpiredEntries();
        return storage.size();
    }

    public synchronized Collection<V> values() {
        Collection<V> values = new ArrayList<V>(storage.size());
        
        for (K key : storage.keySet()) {
            CacheEntry<K,V> value = storage.get(key);
            if (value!=null) {
                values.add(value.getValue());
            }
        }

        return values;
    }

    @Override
    public String toString() {
        return "Cache("+storage+")";
    }
    
    ///////////////////////////////////////////////////////
    // internal helper methods
    ///////////////////////////////////////////////////////
    
    private synchronized void ensureThatAtLeastOneMoreEntryCanBePutted() {
        if (storage.size()<maxElements) {
            // still enough space in the storage
            return;
        }
        
        // try the soft way
        K remainingKey = removeExpiredEntries();
        
        if (storage.size()>maxElements-1) {
            // do the hard way: remove one element
            if (remainingKey!=null) {
                // remove
                storage.remove(remainingKey);
            } else {
                // could not remove: should never happens
                throw new IllegalStateException("no remainingKey found, but storage is not empty: "+storage);
            }
        }
    }
    
    /**
     * @return any of the remaining keys after cleanup;
     *         null if no entry remains in the storage
     */
    private synchronized K removeExpiredEntries() {
        K remainingKey = null;
        
        // find expired entries
        Collection<K> keysToRemove = new ArrayList<K>(storage.size());
        for (Map.Entry<K, CacheEntry<K,V>> entry : storage.entrySet()) {
            if (entry.getValue().isExpired()) {
                keysToRemove.add(entry.getKey());
            } else {
                remainingKey = entry.getKey();
            }
        }
        
        // delete expired entries
        for (K keyToRemove : keysToRemove) {
            storage.remove(keyToRemove);
        }
        
        return remainingKey;
    }
}
