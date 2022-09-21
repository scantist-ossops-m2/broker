const logger = require('../log');
const socket = require('./socket');
const relay = require('../relay');
const version = require('../version');
const { maskToken } = require('../token');
const promBundle = require('express-prom-bundle');
// import WebSocket, { WebSocketServer } from 'ws';

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

      // strip the leading url
      req.url = req.url.slice(`/broker/${token}`.length);
      logger.debug({ url: req.url }, 'request');

      next();
    },
    relay.request(filters.public),
  );

  app.post(
    '/broker-data/:brokerToken/:streamingId',
    (req, res, next) => {
      const token = req.params.brokerToken;
      const sid = req.params.streamingId;
      console.log("Handling broker-data request", token, sid, req.params);
      const maskedToken = maskToken(token);
      req.maskedToken = maskedToken;

      const streamHandler = relay.streamingResponse(token);
      let ioJson = "";
      let ioJsonSize = -1;

      // console.log("Handling broker-data request - io bits", JSON.parse(req.body));
      // streamHandler(sid, null, false, JSON.parse(req.body))
      // req.on('status', data => console.log('Received status event on request', data));
      // req.on('error', data => console.log('Received error event on request', data));
      // req.on('pause', data => console.log('Received pause event on request', data));
      // req.on('readable', data => console.log('Received readable event on request', data));
      // req.on('close', data => console.log('Received close event on request', data));
      req.on('data', function (data) {
        // console.log('Received data event');
        let bytesRead = 0;
        if (ioJsonSize === -1) {
          bytesRead += 4;
          ioJsonSize = data.readUInt32LE();
          console.log(`The metadata from the request is a total of ${ioJsonSize} bytes`);
        }

        if (ioJsonSize > 0 && ioJson.length < ioJsonSize) {
          const bytesToRead = Math.min(ioJsonSize - ioJson.length, data.length);
          ioJson += data.toString('utf8', bytesRead, bytesToRead);
          bytesRead += bytesToRead;

          if (ioJson.length === ioJsonSize) {
            console.log("Handling broker-data request - io bits", JSON.parse(ioJson));
            streamHandler(sid, null, false, JSON.parse(ioJson))
          } else {
            // console.log(`Was unable to fit all information into a single data object - current size ${ioJson.length}, expected size ${ioJsonSize}`);
          }
        }

        if (bytesRead >= data.length) {
          return;
        }

        // console.log("Handling broker-data request - data part");
        streamHandler(sid, data.subarray(bytesRead, data.length), false, null);
      }).on('end', function () {
        console.log("Handling broker-data request - end part");
        streamHandler(sid, null, true, null);
      });

      // // check if we have this broker in the connections
      // if (!connections.has(token)) {
      //   logger.warn({ maskedToken }, 'no matching connection found');
      //   return res.status(404).json({ ok: false });
      // }
      //
      // // Grab a first (newest) client from the pool
      // res.locals.io = connections.get(token)[0].socket;
      //
      // // strip the leading url
      // req.url = req.url.slice(`/broker/${token}`.length);
      // logger.debug({ url: req.url }, 'request');


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
