/*
 * Copyright (c) 2011-2026 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
package io.vertx.core.net.impl;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.impl.ContextInternal;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetClientOptions;
import io.vertx.core.net.NetServerOptions;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.SSLOptions;
import io.vertx.test.core.VertxTestBase;
import io.vertx.test.tls.Cert;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class TCPServerBaseSSLUpdateTest extends VertxTestBase {

  @Test
  public void testConnectionWhileSslUpdateIsPending() throws Exception {
    NetServerOptions options = new NetServerOptions().setSsl(true).setKeyCertOptions(Cert.SERVER_JKS.get());
    Promise<Void> releaseUpdate = Promise.promise();
    AtomicBoolean delayUpdate = new AtomicBoolean();
    SSLHelper helper = delayedHelper(options, delayUpdate, releaseUpdate);
    NetServerImpl server = createServer(options, () -> helper);
    NetClient client = vertx.createNetClient(new NetClientOptions()
      .setSsl(true)
      .setTrustAll(true)
      .setHostnameVerificationAlgorithm(""));
    server.connectHandler(socket -> socket.write("ready"));
    try {
      server.listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      SslContextProvider original = server.sslContextProvider();
      assertNotNull(original);
      delayUpdate.set(true);
      Future<Boolean> update = server.updateSSLOptions(options.getSslOptions(), true);
      assertFalse(update.isComplete());

      NetSocket socket = client.connect(server.actualPort(), "127.0.0.1")
        .toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      assertSame(original, server.sslContextProvider());
      socket.close();

      releaseUpdate.complete();
      assertTrue(update.toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS));
    } finally {
      releaseUpdate.tryComplete();
      client.close();
      server.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    }
  }

  @Test
  public void testSharedConnectionsWhileSslUpdateIsPending() throws Exception {
    NetServerOptions options = new NetServerOptions().setSsl(true).setKeyCertOptions(Cert.SERVER_JKS.get());
    Promise<Void> releaseUpdate = Promise.promise();
    AtomicBoolean delayUpdate = new AtomicBoolean();
    SSLHelper helper = delayedHelper(options, delayUpdate, releaseUpdate);
    NetServerImpl first = createServer(options, () -> helper);
    NetServerImpl second = createServer(options, () -> helper);
    CountDownLatch firstAccepted = new CountDownLatch(1);
    CountDownLatch secondAccepted = new CountDownLatch(1);
    first.connectHandler(socket -> firstAccepted.countDown());
    second.connectHandler(socket -> secondAccepted.countDown());
    NetClient client = vertx.createNetClient(new NetClientOptions()
      .setSsl(true)
      .setTrustAll(true)
      .setHostnameVerificationAlgorithm(""));
    SocketAddressImpl address = new SocketAddressImpl(-1, "127.0.0.1");
    try {
      first.listen(address).toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      second.listen(address).toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      SslContextProvider original = first.sslContextProvider();
      assertSame(original, second.sslContextProvider());
      delayUpdate.set(true);
      Future<Boolean> update = second.updateSSLOptions(options.getSslOptions(), true);
      assertFalse(update.isComplete());

      for (int i = 0; i < 6; i++) {
        NetSocket socket = client.connect(first.actualPort(), "127.0.0.1")
          .toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
        socket.close();
      }
      assertTrue(firstAccepted.await(10, TimeUnit.SECONDS));
      assertTrue(secondAccepted.await(10, TimeUnit.SECONDS));
      assertSame(original, second.sslContextProvider());

      releaseUpdate.complete();
      assertTrue(update.toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS));
    } finally {
      releaseUpdate.tryComplete();
      client.close();
      second.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      first.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    }
  }

  @Test
  public void testOldUpdateDoesNotAffectRelistenedServer() throws Exception {
    NetServerOptions options = new NetServerOptions().setSsl(true).setKeyCertOptions(Cert.SERVER_JKS.get());
    Promise<Void> releaseUpdate = Promise.promise();
    AtomicBoolean delayUpdate = new AtomicBoolean();
    SSLHelper originalHelper = delayedHelper(options, delayUpdate, releaseUpdate);
    SSLHelper newHelper = new SSLHelper(options, null);
    AtomicInteger helpersCreated = new AtomicInteger();
    NetServerImpl server = createServer(options, () -> helpersCreated.getAndIncrement() == 0 ? originalHelper : newHelper);
    NetClient client = vertx.createNetClient(new NetClientOptions()
      .setSsl(true)
      .setTrustAll(true)
      .setHostnameVerificationAlgorithm(""));
    server.connectHandler(socket -> socket.write("ready"));
    try {
      server.listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      SslContextProvider original = server.sslContextProvider();
      delayUpdate.set(true);
      Future<Boolean> oldUpdate = server.updateSSLOptions(options.getSslOptions(), true);
      assertFalse(oldUpdate.isComplete());
      server.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);

      server.listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      SslContextProvider current = server.sslContextProvider();
      assertNotSame(original, current);
      releaseUpdate.complete();
      assertTrue(oldUpdate.toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS));
      assertSame(current, server.sslContextProvider());
      NetSocket socket = client.connect(server.actualPort(), "127.0.0.1")
        .toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
      socket.close();
    } finally {
      releaseUpdate.tryComplete();
      client.close();
      server.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    }
  }

  private SSLHelper delayedHelper(NetServerOptions options, AtomicBoolean delayUpdate, Promise<Void> releaseUpdate) {
    return new SSLHelper(options, null) {
      @Override
      public Future<SslContextUpdate> updateSslContext(SSLOptions sslOptions, boolean force, ContextInternal ctx) {
        Future<SslContextUpdate> update = super.updateSslContext(sslOptions, force, ctx);
        return delayUpdate.get() ? update.compose(result -> releaseUpdate.future().map(result)) : update;
      }
    };
  }

  private NetServerImpl createServer(NetServerOptions options, Supplier<SSLHelper> helper) {
    return new NetServerImpl((VertxInternal) vertx, options) {
      @Override
      protected SSLHelper createSSLHelper() {
        return helper.get();
      }
    };
  }
}
