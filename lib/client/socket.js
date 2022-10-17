require('../patch-https-request-for-proxying');

const Primus = require('primus');
const relay = require('../relay');
const logger = require('../log');
const WebSocket = require('ws');
const constants = require('../constants');

function createWebSocket(url, token, filters, config, identifyingMetadata) {
  const ws = new WebSocket(url.replace('http://', 'ws://').replace('https://', 'wss://') + "/broker-new", 'ws', {headers: {'Snyk-Broker-Token': token}});
  ws.socketVersion = 2;

  const response = relay.response(filters, config, ws)(token);

  ws.on('open', () => {
    const clientData = JSON.stringify({token, metadata: identifyingMetadata});
    const data = new Buffer(1 + clientData.length);
    data.writeUInt8(constants.MESSAGE_TYPE_IDENTIFY);
    data.write(clientData, 1, 'utf8');
    ws.send(data, {binary: true});
  });

  ws.on('message', data => {
    const messageType = data.readUint8();
    const messageData = JSON.parse(data.toString('utf8', 1, data.length));
    if (messageType !== constants.MESSAGE_TYPE_REQUEST) {
      logger.error(`Unexpected message type ${messageType}`)
      return;
    }

    response(messageData, responseData => {
      const rawData = JSON.stringify(responseData);
      const data = new Buffer(1 + rawData.length);
      data.writeUInt8(constants.MESSAGE_TYPE_RESPONSE);
      data.write(rawData, 1, 'utf8');
      ws.send(data, {binary: true});
    });
  });
  ws.on('error', error => {
    logger.error('error on websocket', error);
  });
  ws.on('close', (code, reason) => {
    logger.error('websocket closed unexpectedly', {code, reason: reason.toString()});
  })

  let noPongTimeout = null;
  let pingStart = null;
  const noPong = () => {
    logger.debug('no pong received by timeout - closing connection');
    ws.close(1000, 'pong timeout');
  };
  const heartbeat = () => {
    logger.debug('sending ping');
    ws.once('pong', (data) => {
      console.log(`pong received after ${Date.now() - pingStart}`);
      logger.debug('pong received - clearing timeout & setting up next ping', {data: data.toString()});
      clearTimeout(noPongTimeout);
      setTimeout(heartbeat, 20000);
    });
    ws.ping(new Date().toUTCString());
    pingStart = Date.now();
    noPongTimeout = setTimeout(noPong, 20000);
  };
  setTimeout(heartbeat, 20000);
  ws.on('ping', (data) => {
    logger.debug('ping received - sending pong', {data: data.toString()});
    ws.pong(new Date().toUTCString());
  });
  return ws;
}

function createLegacyWebSocket(token, url, config, filters, identifyingMetadata) {
  const Socket = Primus.createSocket({
    transformer: 'engine.io',
    parser: 'EJSON',
    plugin: {
      emitter: require('primus-emitter'),
    },
    pathname: `/primus/${token}`,
  });

  // Will exponentially back-off from 0.5 seconds to a maximum of 20 minutes
  // Retry for a total period of around 4.5 hours
  const io = new Socket(url, {
    reconnect: {
      factor: 1.5,
      retries: 30,
      max: 20 * 60 * 1000,
    },
    ping: parseInt(config.socketPingInterval) || 25000,
    pong: parseInt(config.socketPongTimeout) || 10000,
    timeout: parseInt(config.socketConnectTimeout) || 10000,
  });

  io.on('reconnect scheduled', (opts) => {
    const attemptIn = Math.floor(opts.scheduled / 1000);
    logger.warn(
      `Reconnect retry #${opts.attempt} of ${opts.retries} in about ${attemptIn}s`,
    );
  });

  io.on('reconnect failed', () => {
    io.end();
    logger.error('Reconnect failed');
    process.exit(1);
  });

  logger.info({url}, 'broker client is connecting to broker server');

  const response = relay.response(filters, config, io);
  const streamingResponse = relay.streamingResponse;

  // RS note: this bind doesn't feel right, it feels like a sloppy way of
  // getting the filters into the request function.
  io.on('chunk', streamingResponse(token));
  io.on('request', response(token));
  io.on('error', ({type, description}) => {
    if (type === 'TransportError') {
      logger.error({type, description}, 'Failed to connect to broker server');
    } else {
      logger.warn({type, description}, 'Error on websocket connection');
    }
  });
  io.on('open', () => {
    logger.info(
      {url, token, identifyingMetadata},
      'successfully established a websocket connection to the broker server',
    );
    const clientData = {token, metadata: identifyingMetadata};
    io.send('identify', clientData);
  });

  io.on('close', () => {
    logger.warn(
      {url, token},
      'websocket connection to the broker server was closed',
    );
  });

  io.socketVersion = 1;
  io.socketType = 'client';

  // only required if we're manually opening the connection
  // io.open();
  return io;
}

module.exports = ({ url, token, filters, config, identifyingMetadata }) => {
  if (!token) {
    // null, undefined, empty, etc.
    logger.error({ token }, 'missing client token');
    const error = new ReferenceError(
      'BROKER_TOKEN is required to successfully identify itself to the server',
    );
    error.code = 'MISSING_BROKER_TOKEN';
    throw error;
  }

  if (!url) {
    // null, undefined, empty, etc.
    logger.error({ url }, 'missing broker url');
    const error = new ReferenceError(
      'BROKER_SERVER_URL is required to connect to the broker server',
    );
    error.code = 'MISSING_BROKER_SERVER_URL';
    throw error;
  }

  // return createWebSocket(url, token, filters, config, identifyingMetadata);

  return createLegacyWebSocket(token, url, config, filters, identifyingMetadata);
};
