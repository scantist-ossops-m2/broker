require('../patch-https-request-for-proxying');

const Primus = require('primus');
const relay = require('../relay');
const logger = require('../log');
const { axiosInstance } = require('../axios');

async function fetchJwt() {
  let oauthResponse = await axiosInstance.request({
    url: 'http://localhost:8080/oauth2/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    auth: {
      username: 'broker-connection-a',
      password: 'secret',
    },
    data: 'grant_type=client_credentials',
  });

  let jwt = oauthResponse.data.access_token;
  let type = oauthResponse.data.token_type;
  let expiresIn = oauthResponse.data.expires_in;

  return [expiresIn, `${type} ${jwt}`];
}

async function createWebSocket(
  token,
  url,
  config,
  filters,
  identifyingMetadata,
  serverId,
) {
  const Socket = Primus.createSocket({
    transformer: 'engine.io',
    parser: 'EJSON',
    plugin: {
      emitter: require('primus-emitter'),
    },
    pathname: `/primus/${token}`,
  });

  if (serverId) {
    const urlWithServerId = new URL(url);
    urlWithServerId.searchParams.append('server_id', serverId);
    url = urlWithServerId.toString();
  }

  const [expiresIn, authHeader] = await fetchJwt();

  // Will exponentially back-off from 0.5 seconds to a maximum of 20 minutes
  // Retry for a total period of around 4.5 hours
  const io = new Socket(url, {
    transport: {
      extraHeaders: {
        'Authorization': authHeader,
      }
    },
    reconnect: {
      factor: 1.5,
      retries: 30,
      max: 20 * 60 * 1000,
    },
    ping: parseInt(config.socketPingInterval) || 25000,
    pong: parseInt(config.socketPongTimeout) || 10000,
    timeout: parseInt(config.socketConnectTimeout) || 10000,
  });

  let timeoutHandlerId = undefined;
  let timeoutHandler = async () => {};
  timeoutHandler = async () => {
    clearTimeout(timeoutHandlerId);
    const [expiresIn, authHeader] = await fetchJwt();

    io.transport.extraHeaders['Authorization'] = authHeader;
    io.end();
    io.open();
    timeoutHandlerId = setTimeout(timeoutHandler, (expiresIn - 60) * 1000);
  };

  timeoutHandlerId = setTimeout(timeoutHandler,  (expiresIn - 60) * 1000);

  io.on('incoming::error', (e) => {
    io.emit('error', {type: e.type, description: e.description});
  });

  io.on('identify', (serverData) => {
    io.capabilities = serverData.capabilities;
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

  logger.info(
    { url, serverId },
    'broker client is connecting to broker server',
  );

  const response = relay.response(filters, config, io, serverId);
  const streamingResponse = relay.streamingResponse;

  // RS note: this bind doesn't feel right, it feels like a sloppy way of
  // getting the filters into the request function.
  io.on('chunk', streamingResponse(token));
  io.on('request', response(token));
  io.on('error', ({ type, description }) => {

    if (type === 'TransportError') {
      // if (description === '401') {
      //   logger.error(`Received a 401 error trying to connect to the Snyk Server. There are two likely explanations:
      //   * There was an error fetching the auth token, and the header has not been properly set
      //   * There is a proxy in use and the authentication details are not set
      //   `);
      //   io.end();
      //   process.exit(2);
      // } else if (description === '403') {
      //   logger.error(`Received a 403 error trying to connect to the Snyk Server. There are two likely explanations:
      //   * The authentication token is invalid - it is expired, malformed, not signed by Snyk, or some other error
      //   * There is a proxy in use and the authentication details are incorrect
      //   `);
      //   io.end();
      //   process.exit(3);
      // } else {
        logger.error({ type, description }, 'Failed to connect to broker server');
      // }
    } else {
      logger.warn({ type, description }, 'Error on websocket connection');
    }
  });
  io.on('open', () => {
    const metadata = {
      capabilities: identifyingMetadata.capabilities,
      clientId: identifyingMetadata.clientId,
      preflightChecks: identifyingMetadata.preflightChecks,
      version: identifyingMetadata.version,
    };
    logger.info(
      { url, token, metadata },
      'successfully established a websocket connection to the broker server',
    );
    const clientData = { token, metadata: identifyingMetadata };
    io.send('identify', clientData);
  });

  io.on('close', () => {
    logger.warn(
      { url, token },
      'websocket connection to the broker server was closed',
    );
  });

  io.on('data', (data) => {
    if (data.endReason === 'TOKEN_EXPIRED') {
      logger.warn({ url, token, data }, 'websocket connection to the broker server was closed - fetching new token and reconnecting');
      timeoutHandler();
    }
  });

  io.socketVersion = 1;
  io.socketType = 'client';

  // only required if we're manually opening the connection
  // io.open();
  return io;
}

module.exports = async ({
  url,
  token,
  filters,
  config,
  identifyingMetadata,
  serverId,
}) => {
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

  return await createWebSocket(
    token,
    url,
    config,
    filters,
    identifyingMetadata,
    serverId,
  );
};
