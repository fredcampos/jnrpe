/*******************************************************************************
 * Copyright (c) 2007, 2014 Massimiliano Ziccardi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package it.jnrpe;

import it.jnrpe.commands.CommandRepository;
import it.jnrpe.events.IJNRPEEventListener;
import it.jnrpe.plugins.IPluginRepository;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Builder for the {@link JNRPE} object.
 * 
 * @author Massimiliano Ziccardi
 */
public final class JNRPEBuilder {

    /**
     * Default read timeout is 10 seconds.
     */
    private static final int DEFAULT_READ_TIMEOUT = 10;

    /**
     * Default write timeout is 60 seconds.
     */
    private static final int DEFAULT_WRITE_TIMEOUT = 60;

    /**
     * The plugin repository.
     */
    private final IPluginRepository pluginRepository;

    /**
     * The command repository.
     */
    private final CommandRepository commandRepository;

    /**
     * The list of accepted hosts.
     */
    private final Collection<String> acceptedHosts = new ArrayList<String>();

    /**
     * All the event listeners.
     */
    private final Collection<IJNRPEEventListener> eventListeners = new ArrayList<IJNRPEEventListener>();

    /**
     * Sets if macros ($ARGxx$) should be expanded or not.
     */
    private boolean acceptParams = false;

    /**
     * Maximum number of concurrent connections.
     */
    private int maxAcceptedConnections = JNRPE.DEFAULT_MAX_ACCEPTED_CONNECTIONS;

    /**
     * The JNRPE charset.
     */
    private Charset charset = Charset.defaultCharset();

    /**
     * Read timeout in seconds.
     */
    private int readTimeout = DEFAULT_READ_TIMEOUT;

    /**
     * Write timeout in seconds.
     */
    private int writeTimeout = DEFAULT_WRITE_TIMEOUT;

    /**
     * Constructor.
     * 
     * @param jnrpePluginRepository
     *            The plugin repository
     * @param jnrpeCommandRepository
     *            The command repository
     */
    private JNRPEBuilder(final IPluginRepository jnrpePluginRepository, final CommandRepository jnrpeCommandRepository) {

        if (jnrpePluginRepository == null || jnrpeCommandRepository == null) {
            throw new IllegalArgumentException("Both plugin and command repository can't be null");
        }

        this.pluginRepository = jnrpePluginRepository;
        this.commandRepository = jnrpeCommandRepository;
    }

    /**
     * Entry point for the builder.
     * 
     * @param pluginRepository
     *            The plugin repository
     * @param commandRepository
     *            The command repository
     * @return this
     */
    public static JNRPEBuilder forRepositories(final IPluginRepository pluginRepository, final CommandRepository commandRepository) {

        return new JNRPEBuilder(pluginRepository, commandRepository);
    }

    /**
     * Pass <code>true</code> if $ARGxx$ macros should be expanded.
     * 
     * @param accept
     *            <code>true</code> if $ARGxx$ macros should be expanded.
     * @return this
     */
    public JNRPEBuilder acceptParams(final boolean accept) {
        this.acceptParams = accept;
        return this;
    }

    /**
     * Adds a client host to the list of accepted hosts.
     * 
     * @param hostName
     *            the hostname or ip address
     * @return this
     */
    public JNRPEBuilder acceptHost(final String hostName) {
        this.acceptedHosts.add(hostName);
        return this;
    }

    /**
     * Adds a listener to the list of event listener.
     * 
     * @param listener
     *            the listener
     * @return this
     */
    public JNRPEBuilder withListener(final IJNRPEEventListener listener) {
        this.eventListeners.add(listener);
        return this;
    }

    /**
     * Sets the charset to be used.
     * 
     * @param newCharset
     *            the charset to be used
     * @return this
     */
    public JNRPEBuilder withCharset(final Charset newCharset) {
        this.charset = newCharset;
        return this;
    }

    /**
     * Sets the maximum number of accepted connections.
     * 
     * @param maxConnections
     *            the maximum number of accepted connections.
     * @return this
     */
    public JNRPEBuilder withMaxAcceptedConnections(final int maxConnections) {
        this.maxAcceptedConnections = maxConnections;
        return this;
    }

    /**
     * Sets the read timeout in seconds. Default is
     * {@link #DEFAULT_READ_TIMEOUT} seconds.
     * 
     * @param readTimeoutSecs
     *            the new read timeout in seconds
     * @return this
     */
    public JNRPEBuilder withReadTimeout(final int readTimeoutSecs) {
        this.readTimeout = readTimeoutSecs;
        return this;
    }

    /**
     * Sets the write timeout in seconds. Default is
     * {@link #DEFAULT_WRITE_TIMEOUT} seconds.
     * 
     * @param writeTimeoutSecs
     *            the new write timeout in seconds
     * @return this
     */
    public JNRPEBuilder withWriteTimeout(final int writeTimeoutSecs) {
        this.writeTimeout = writeTimeoutSecs;
        return this;
    }

    /**
     * Builds the configured JNRPE instance.
     * 
     * @return the configured JNRPE instance
     */
    public JNRPE build() {
        JNRPE jnrpe = new JNRPE(pluginRepository, commandRepository, charset, acceptParams, acceptedHosts, maxAcceptedConnections, readTimeout,
                writeTimeout, eventListeners);

        return jnrpe;
    }
}
