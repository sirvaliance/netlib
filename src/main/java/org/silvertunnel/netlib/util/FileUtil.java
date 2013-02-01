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

package org.silvertunnel.netlib.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.logging.Logger;

/**
 * This class contains methods to read and to write UTF-8 encoded text files from file system,
 * and to read UTF-8 encoded text files from CLASSPTH.
 * 
 * @author hapke
 */
public class FileUtil {
    private static final Logger log = Logger.getLogger(FileUtil.class.getName());
    
    private static final String FILE_CHARSET_NAME = "UTF-8";

    private static FileUtil instance = new FileUtil();
    
    /**
     * @return singleton instance
     */
    public static FileUtil getInstance() {
        return instance;
    }

    protected FileUtil() {
    }
    
    /**
     * Change the contents of text file in its entirety, overwriting any existing text.
     *
     * Do nothing in the case of an error.
     *     
     * @param file       file to write; not null
     * @param content    String to write; not null
     * @throws IOException 
     */
    public void writeFile(File file, String content) throws IOException {
        Writer output = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(file), FILE_CHARSET_NAME));
        try {
            output.write(content);
        } finally {
            output.close();
        }
    }
    
    /**
     * Read UTF-8 encoded text file from file system.
     * 
     * @param file    file to read; not null
     * @return file content
     * @throws IOException 
     */
    public String readFile(File file) throws IOException {
        BufferedReader input = new BufferedReader(new InputStreamReader(new FileInputStream(file), FILE_CHARSET_NAME));
        try {
            final int BUFFER_SIZE = 1024;
            StringBuilder contents = new StringBuilder(BUFFER_SIZE);
            
            // copy from input stream
            char[] c = new char[BUFFER_SIZE];
            int len;
            while ((len=input.read(c))>0) {
                contents.append(c, 0, len);
            }

            return contents.toString();

        } finally {
            input.close();
        }
    }
    
    /** 
     * Read UTF-8 encoded text file from CLASSPATH.
     * 
     * @param filePath      name of file to open; not null.
     *                      The file can reside anywhere in the classpath
     * @return the file content; null in the case of an error
     */
    public String readFileFromClasspath(String filePath) throws IOException {
        return readFileFromInputStream(getClass().getResourceAsStream(filePath));
    }
 
    /**
     * Read UTF-8 encoded text file from InputStream.
     *  
     * @param is
     * @return the text file content
     * @throws IOException
     */
    public String readFileFromInputStream(InputStream is) throws IOException {
        BufferedReader input = new BufferedReader(new InputStreamReader(is, FILE_CHARSET_NAME));
        try {
            final int BUFFER_SIZE = 1024;
            StringBuilder contents = new StringBuilder(BUFFER_SIZE);
            
            // copy from input stream
            char[] c = new char[BUFFER_SIZE];
            int len;
            while ((len=input.read(c))>0) {
                contents.append(c, 0, len);
            }

            return contents.toString();

        } finally {
            input.close();
        }
    }
}
