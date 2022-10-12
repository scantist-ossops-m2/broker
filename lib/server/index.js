const {decrementSocketConnectionGauge, incrementSocketConnectionGauge} = require("../metrics");

const logger = require('../log');
const socket = require('./socket');
const relay = require('../relay');
const version = require('../version');
const { maskToken } = require('../token');
const promBundle = require('express-prom-bundle');
const constants = require('../constants');
const { WebSocketServer } = require('ws');

module.exports = ({ config = {}, port = null, filters = {} }) => {
  logger.info({ version }, 'running in server mode');

  // start the local webserver to listen for relay requests
  const { app, server } = require('../webserver')(config, port);

  // bind the socket server to the web server
  const { io, connections } = socket({
    server,
    filters: filters.private,
    config,
  });

  // basic prometheus metrics
  const metricsMiddleware = promBundle({
    buckets: [0.5, 1, 2, 5, 10, 30, 60, 120, 300],
    includeMethod: true,
    includePath: false,
    metricsPath: '/metrics',
    promClient: {
      collectDefaultMetrics: {
        timeout: 3000,
      },
    },
  });

  app.use(metricsMiddleware);

  app.get('/connection-status/:token', (req, res) => {
    const token = req.params.token;
    const maskedToken = maskToken(token);

    if (connections.has(token)) {
      const clientsMetadata = connections.get(token).map((conn) => ({
        version: conn.metadata && conn.metadata.version,
        filters: conn.metadata && conn.metadata.filters,
      }));
      return res.status(200).json({ ok: true, clients: clientsMetadata });
    }
    logger.warn({ maskedToken }, 'no matching connection found');
    return res.status(404).json({ ok: false });
  });

  app.all(
    '/broker/:token/*',
    (req, res, next) => {
      const token = req.params.token;
      const maskedToken = maskToken(token);
      req.maskedToken = maskedToken;

      // check if we have this broker in the connections
      if (!connections.has(token)) {
        logger.warn({ maskedToken }, 'no matching connection found');
        return res.status(404).json({ ok: false });
      }

      // Grab a first (newest) client from the pool
      res.locals.io = connections.get(token)[0].socket;
      res.locals.socketVersion = connections.get(token)[0].socketVersion;
      res.locals.capabilities = connections.get(token)[0].metadata.capabilities;

      // strip the leading url
      req.url = req.url.slice(`/broker/${token}`.length);
      logger.debug({ url: req.url }, 'request');

      next();
    },
    relay.request(filters.public),
  );

  const wss = new WebSocketServer({server, path: '/broker-new'});
  wss.on('connection', (socket, req) => {
    const token = req.headers['snyk-broker-token'];
    const streamHandler = relay.streamingResponse(token);
    let ioJson = "";
    // let ioJsonSize = -1;

    let noPongTimeout = null;
    let pingStart = null;
    const noPong = () => {
      logger.debug('no pong received by timeout - closing connection');
      socket.close(1000, 'pong timeout');
    };
    const heartbeat = () => {
      logger.debug('sending ping');
      socket.ping(new Date().toUTCString());
      pingStart = Date.now();
      socket.once('pong', (data) => {
        console.log(`pong received after ${Date.now() - pingStart}`);
        logger.debug('pong received - clearing timeout & setting up next ping', {data: data.toString()});
        clearTimeout(noPongTimeout);
        setTimeout(heartbeat, 20000);
      });
      noPongTimeout = setTimeout(noPong, 20000);
    };
    setTimeout(heartbeat, 20000);
    socket.on('error', error => {
      logger.error('error on websocket', error);
    });
    socket.on('close', (code, reason) => {
      logger.error('websocket closed unexpectedly', {code, reason: reason.toString()});
    })
    socket.on('ping', (data) => {
      logger.debug('ping received - sending pong', {data: data.toString()});
      socket.pong(new Date().toUTCString());
    });
    socket.on('message', data => {
      try {
        logger.trace(`Received message of size ${data.length}`);
        let bytesRead = 0;
        const messageType = data.readUint8();
        logger.trace(`Received message with type [${messageType}]`);
        bytesRead++;
        if (messageType === constants.MESSAGE_TYPE_IDENTIFY) {
          const clientData = JSON.parse(data.toString('utf8', bytesRead, data.length));
          const maskedToken = maskToken(token);

          logger.info(
            { maskedToken, metadata: clientData.metadata },
            'new client connection identified',
          );

          const clientPool = connections.get(token) || [];
          clientPool.unshift({ socket, socketVersion: 2, metadata: clientData.metadata });
          connections.set(token, clientPool);

          // socket.on('chunk', streamingResponse(token));
          // socket.on('request', response(token));

          incrementSocketConnectionGauge();
          return;
        }
        const streamingId = data.toString('utf8', bytesRead, bytesRead + 36);
        bytesRead += 36;
        // This will need to be quite a bit more complex to handle actual requests coming from the Client (e.g., WebHooks)
        switch(messageType) {
          case constants.MESSAGE_TYPE_DATA:
            break;
          case constants.MESSAGE_TYPE_EOF:
            streamHandler(streamingId, null, true, null, null);
            return;
          case constants.MESSAGE_TYPE_HEADERS:
            ioJson = data.toString('utf8', bytesRead, data.length);
            streamHandler(streamingId, null, false, JSON.parse(ioJson), null)
            return;
          default:
            logger.error(`Unknown message type ${messageType}`);
            return;
        }

        // if (ioJsonSize === -1) {
        //   ioJsonSize = data.readUInt32LE();
        //   bytesRead += 4;
        //   logger.debug(`The metadata from the request is a total of ${ioJsonSize} bytes`);
        // }
        //
        // if (ioJsonSize > 0 && ioJson.length < ioJsonSize) {
        //   const endPosition = Math.min(bytesRead + ioJsonSize - ioJson.length, data.length);
        //   logger.trace('Reading ioJson', {bytesRead, endPosition});
        //   ioJson += data.toString('utf8', bytesRead, endPosition);
        //   bytesRead = endPosition;
        //
        //   if (ioJson.length === ioJsonSize) {
        //     logger.trace("Converting to json", {ioJson});
        //     logger.debug("Handling broker-data request - io bits", {json: JSON.parse(ioJson)});
        //     streamHandler(streamingId, null, false, JSON.parse(ioJson), null);
        //   } else {
        //     logger.trace(`Was unable to fit all information into a single data object - current size ${ioJson.length}, expected size ${ioJsonSize}`);
        //   }
        // }

        if (bytesRead < data.length) {
          logger.trace("Handling broker-data request - data part");
          streamHandler(streamingId, data.subarray(bytesRead, data.length), false, null, streamBuffer => {
            if (!socket.isPaused) {
              logger.trace('pausing request stream');
              socket.pause();
              streamBuffer.once('drain', () => {
                logger.trace('resuming request stream')
                socket.resume();
              });
            }
          });
        }
      } catch (e) {
        logger.error(e);
      }
    })
    socket.on('close', (code, closeReason) => {
      if (token) {
        const maskedToken = maskToken(token);
        const clientPool = connections
          .get(token)
          .filter((_) => _.socket !== socket);
        logger.info(
          {
            closeReason,
            maskedToken,
            remainingConnectionsCount: clientPool.length,
          },
          'client connection closed',
        );
        if (clientPool.length) {
          connections.set(token, clientPool);
        } else {
          logger.info({ maskedToken }, 'removing client');
          connections.delete(token);
        }
        decrementSocketConnectionGauge();
      }
    })
  });

  app.post(
    '/broker-data/:brokerToken/:streamingId',
    (req, res, next) => {
      const token = req.params.brokerToken;
      const streamingId = req.params.streamingId;
      const maskedToken = maskToken(token);
      logger.info("Handling broker-data request", {maskedToken, streamingId});
      req.maskedToken = maskedToken;

      const streamHandler = relay.streamingResponse(token);
      let ioJson = "";
      let ioJsonSize = -1;

      req.on('data', function (data) {
        try {
          logger.trace(`Received data event of size ${data.length}`);
          let bytesRead = 0;
          if (ioJsonSize === -1) {
            bytesRead += 4;
            ioJsonSize = data.readUInt32LE();
            logger.debug(`The metadata from the request is a total of ${ioJsonSize} bytes`);
          }

          if (ioJsonSize > 0 && ioJson.length < ioJsonSize) {
            const endPosition = Math.min(bytesRead + ioJsonSize - ioJson.length, data.length);
            logger.trace('Reading ioJson', {bytesRead, endPosition});
            ioJson += data.toString('utf8', bytesRead, endPosition);
            bytesRead = endPosition;

            if (ioJson.length === ioJsonSize) {
              logger.trace("Converting to json", {ioJson});
              logger.debug("Handling broker-data request - io bits", {json: JSON.parse(ioJson)});
              streamHandler(streamingId, null, false, JSON.parse(ioJson), null);
            } else {
              logger.trace(`Was unable to fit all information into a single data object - current size ${ioJson.length}, expected size ${ioJsonSize}`);
            }
          }

          if (bytesRead < data.length) {
            logger.trace("Handling broker-data request - data part");
            streamHandler(streamingId, data.subarray(bytesRead, data.length), false, null, streamBuffer => {
              logger.trace('pausing request stream');
              req.pause();
              streamBuffer.once('drain', () => {
                logger.trace('resuming request stream')
                req.resume();
              });
            });
          }
        } catch (e) {
          logger.error(e);
        }
      }).on('end', function () {
        logger.debug("Handling broker-data request - end part");
        streamHandler(streamingId, null, true, null, null);
        res.status(200).json({});
      }).on('error', err => {
        logger.error('received error handling POST from client', {err});
        streamHandler(streamingId, null, true, null, null);
        res.status(500).json({err});
      });
    },
  );

  app.get('/', (req, res) => res.status(200).json({ ok: true, version }));

  app.get('/healthcheck', (req, res) =>
    res.status(200).json({ ok: true, version }),
  );

  // const wss = new WebSocketServer({port: 7340});
  //
  // wss.on('connection', function connection(ws) {
  //   ws.on('message', function message(data) {
  //     console.log('received: %s', data);
  //   });
  //
  //   ws.send('something');
  // });

  return {
    io,
    close: (done) => {
      logger.info('server websocket is closing');
      server.close();
      io.destroy(function () {
        logger.info('server websocket is closed');
        if (done) {
          return done();
        }
      });
    },
  };
};
