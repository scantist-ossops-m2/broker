const request = require('request');
const undefsafe = require('undefsafe');
const parse = require('url').parse;
const format = require('url').format;
const { v4: uuid } = require('uuid');
const Filters = require('./filters');
const { replace, replaceUrlPartialChunk } = require('./replace-vars');
const tryJSONParse = require('./try-json-parse');
const logger = require('./log');
const version = require('./version');
const { maskToken } = require('./token');
const stream = require('stream');
const NodeCache = require('node-cache');
const metrics = require('./metrics');
const config = require('./config');
const constants = require('./constants');
const {initStream, pipeStream} = require('./stream-posts');

module.exports = {
  request: requestHandler,
  response: responseHandler,
  streamingResponse: streamResponseHandler,
};

const streams = new NodeCache({
  stdTTL: parseInt(config.cacheExpiry) || 3600, // 1 hour
  checkperiod: parseInt(config.cacheCheckPeriod) || 60, // 1 min
  useClones: false,
});

function streamResponseHandler(token) {
  return (streamingID, chunk, finished, ioResponse, waitForDrainCb) => {
    const streamFromId = streams.get(streamingID);

    if (streamFromId) {
      const { streamBuffer, response } = streamFromId;
      let { streamSize } = streamFromId;

      if (streamBuffer) {
        if (ioResponse) {
          response.status(ioResponse.status).set(ioResponse.headers);
        }
        let waitForDrain = false;
        if (chunk) {
          streamSize += chunk.length;
          waitForDrain = !streamBuffer.write(chunk);
          streams.set(streamingID, { streamSize, streamBuffer, response });
        }
        if (finished) {
          streamBuffer.end();
          streams.del(streamingID);
          metrics.observeResponseSize({
            bytes: streamSize,
            isStreaming: true,
          });
        } else {
          if (waitForDrain && waitForDrainCb) {
            waitForDrainCb(streamBuffer);
          }
        }
      } else {
        logger.warn({ streamingID, token }, 'discarding binary chunk');
      }
    } else {
      logger.warn(
        { streamingID, token },
        'trying to write into a closed stream',
      );
    }
  };
}

// 1. Request coming in over HTTP conn (logged)
// 2. Filter for rule match (log and block if no match)
// 3. Relay over websocket conn (logged)
// 4. Get response over websocket conn (logged)
// 5. Send response over HTTP conn
function requestHandler(filterRules) {
  const filters = Filters(filterRules);

  return (req, res) => {
    const logContext = {
      url: req.url,
      method: req.method,
      headers: req.headers,
      requestId: req.headers['snyk-request-id'] || uuid(),
      maskedToken: req.maskedToken,
    };

    logger.debug(logContext, 'received request over HTTP connection');
    filters(req, (error, result) => {
      if (error) {
        const reason =
          'Request does not match any accept rule, blocking HTTP request';
        error.reason = reason;
        logContext.error = error;
        logger.warn(logContext, reason);
        // TODO: respect request headers, block according to content-type
        return res
          .status(401)
          .send({ message: error.message, reason, url: req.url });
      }

      req.url = result.url;
      logContext.ioUrl = result.url;

      // check if this is a streaming request for binary data
      if (result.stream || res?.locals?.capabilities?.includes('post-streams')) {
        const streamingID = uuid();
        const streamBuffer = new stream.PassThrough({highWaterMark: 1048576});
        logContext.streamingID = streamingID;
        logger.debug(
          logContext,
          'sending stream request over websocket connection',
        );

        streams.set(streamingID, {
          response: res,
          streamBuffer,
          streamSize: 0,
        });
        streamBuffer.pipe(res);

        if (res.locals.socketVersion === 1) {
          res.locals.io.send(
            'request',
            {
              url: req.url,
              method: req.method,
              body: req.body,
              headers: req.headers,
              streamingID,
            },
            () => {
              // Streaming requests should not be handled using the emit function
              // but rather by sending 'chunk' messages
              const msg = 'Broker client does not support streaming requests';
              logger.error(logContext, msg);
              return res.status(501).send({message: msg});
            },
          );
        } else {
          const rawData = JSON.stringify({
            url: req.url,
            method: req.method,
            body: req.body,
            headers: req.headers,
            streamingID,
          });
          const data = new Buffer(1 + rawData.length);
          data.writeInt8(constants.MESSAGE_TYPE_REQUEST);
          data.write(rawData, 1,'utf8');
          res.locals.io.send(data, {binary: true})
        }

        return;
      }

      logger.debug(logContext, 'sending request over websocket connection');

      // relay the http request over the websocket, handle websocket response
      res.locals.io.send(
        'request',
        {
          url: req.url,
          method: req.method,
          body: req.body,
          headers: req.headers,
          streamingID: '',
        },
        (ioResponse) => {
          logContext.ioStatus = ioResponse.status;
          logContext.ioHeaders = ioResponse.headers;
          logContext.ioRequestBodyType = typeof ioResponse.body;

          const logMsg = 'sending response back to HTTP connection';
          if (ioResponse.status <= 200) {
            logger.debug(logContext, logMsg);
            let responseBodyString = '';
            if (typeof ioResponse.body === 'string') {
              responseBodyString = ioResponse.body;
            } else if (typeof ioResponse.body === 'object') {
              responseBodyString = JSON.stringify(ioResponse.body);
            }
            if (responseBodyString) {
              const responseBodyBytes = Buffer.byteLength(
                responseBodyString,
                'utf-8',
              );
              metrics.observeResponseSize({
                bytes: responseBodyBytes,
                isStreaming: false,
              });
            } else {
              // fallback metric to let us know if we're recording all response sizes
              // we expect to remove this should it report 0
              metrics.incrementUnableToSizeResponse();
            }
          } else {
            logContext.ioErrorType = ioResponse.errorType;
            logContext.ioOriginalBodySize = ioResponse.originalBodySize;
            logger.warn(logContext, logMsg);
          }

          const httpResponse = res
            .status(ioResponse.status)
            .set(ioResponse.headers);

          const encodingType = undefsafe(
            ioResponse,
            'headers.transfer-encoding',
          );
          try {
            // keep chunked http requests without content-length header
            if (encodingType === 'chunked') {
              httpResponse.write(ioResponse.body);
              httpResponse.end();
            } else {
              httpResponse.send(ioResponse.body);
            }
          } catch (err) {
            logger.error(
              { ...logContext, encodingType, err },
              'error forwarding response',
            );
          }
        },
      );
    });
  };
}

// 1. Request coming in over websocket conn (logged)
// 2. Filter for rule match (log and block if no match)
// 3. Relay over HTTP conn (logged)
// 4. Get response over HTTP conn (logged)
// 5. Send response over websocket conn
function responseHandler(filterRules, config, io) {
  const filters = Filters(filterRules);

  return (brokerToken) =>
    (
      { url, headers = {}, method, body = null, streamingID = '' } = {},
      emit,
    ) => {
      const logContext = {
        url,
        method,
        headers,
        requestId: headers['snyk-request-id'] || uuid(),
        streamingID,
        maskedToken: maskToken(brokerToken),
        transport: io?.socket?.transport?.name ?? 'unknown',
      };

      const realEmit = emit;
      emit = (responseData) => {
        if (responseData instanceof request.Request) {
          logger.trace(logContext, "posting streaming response back to Broker Server");
          pipeStream(responseData, logContext, config, brokerToken, streamingID);
        } else if (streamingID) {
          const body = responseData.body;
          delete responseData.body;
          logger.trace(logContext, "posting fixed response back to Broker Server as it's expecting streaming response", {responseData, body});
          const buffer = initStream(config, brokerToken, streamingID, JSON.stringify(responseData));
          buffer.write(JSON.stringify(body));
          buffer.end();
        } else {
          logger.trace(logContext, "sending fixed response over WebSocket connection", {responseData});
          realEmit(responseData);
        }
      };

      logger.debug(logContext, 'received request over websocket connection');

      filters({ url, method, body, headers }, (filterError, result) => {
        if (filterError) {
          const reason =
            'Response does not match any accept rule, blocking websocket request';
          logContext.error = filterError;
          filterError.reason = reason;
          logger.warn(logContext, reason);
          return emit({
            status: 401,
            body: {
              message: filterError.message,
              reason,
              url,
            },
          });
        }

        if (result.url.startsWith('http') === false) {
          result.url = 'https://' + result.url;
          logContext.resultUrlSchemeAdded = true;
        }

        logContext.httpUrl = result.url;

        if (!headers['user-agent']) {
          headers['user-agent'] = 'Snyk Broker ' + version;
          logContext.userAgentHeaderSet = true;
        }

        if (result.auth) {
          headers.authorization = result.auth;
          logContext.authHeaderSetByRuleAuth = true;
        } else {
          const parsed = parse(result.url);
          if (parsed.auth) {
            // if URL contains basic auth,
            // remove authorization header to prefer auth on the URL.
            if (parsed.auth.includes(':')) {
              delete headers.authorization;
            }

            // if URL contains token auth,
            // put the token in the authorization header
            // instead of on the URL.
            else {
              headers.authorization = `token ${parsed.auth}`;
              // then strip from the url
              delete parsed.auth;
              result.url = format(parsed);
            }

            logContext.authHeaderSetByRuleUrl = true;
          }
        }

        // if the request is all good - and at this point it is, we'll check
        // whether we want to do variable substitution on the body
        //
        // Variable substitution - for those who forgot - is substituting a part
        // of a given string (e.g. "${SOME_ENV_VAR}/rest/of/string")
        // with an env var of the same name (SOME_ENV_VAR).
        // This is used (for example) to substitute the snyk url
        // with the broker's url when defining the target for an incoming webhook.
        if (body) {
          const parsedBody = tryJSONParse(body);

          if (parsedBody.BROKER_VAR_SUB) {
            logContext.bodyVarsSubstitution = parsedBody.BROKER_VAR_SUB;
            for (const path of parsedBody.BROKER_VAR_SUB) {
              let source = undefsafe(parsedBody, path); // get the value
              source = replace(source, config); // replace the variables
              undefsafe(parsedBody, path, source); // put it back in
            }
            body = JSON.stringify(parsedBody);
          }
        }

        // check whether we want to do variable substitution on the headers
        if (headers && headers['x-broker-var-sub']) {
          logContext.headerVarsSubstitution = headers['x-broker-var-sub'];
          for (const path of headers['x-broker-var-sub'].split(',')) {
            let source = undefsafe(headers, path.trim()); // get the value
            source = replace(source, config); // replace the variables
            undefsafe(headers, path.trim(), source); // put it back in
          }
        }

        // remove headers that we don't want to relay
        // (because they corrupt the request)
        [
          'x-forwarded-for',
          'x-forwarded-proto',
          'content-length',
          'host',
          'accept-encoding',
          'content-encoding'
        ].map((_) => delete headers[_]);

        if (brokerToken && io?.socketType === 'server') {
          Object.assign(headers, { 'X-Broker-Token': brokerToken });
        }

        logger.debug(
          logContext,
          'sending websocket request over HTTP connection',
        );

        if (headers['connection']) {
          logger.trace(`replacing connection header [${headers['connection']}] with close`);
          headers['connection'] = 'close';
        } else {
          logger.trace('setting header connection=close');
          headers['connection'] = 'close';
        }

        if (body?.type === 'Buffer')
          body = new Buffer(body.data);

        const req = {
          url: result.url,
          headers: headers,
          method,
          body,
          agentOptions: {
            ca: config.caCert, // Optional CA cert
          },
        };

        // check if this is a streaming request for binary data
        // This only works client -> server, it's not possible to stream data server -> client
        if (streamingID) {
          logger.debug(logContext, 'serving stream request');
          logger.trace('Fowarding request', req, req.body);

          let prevPartialChunk;
          let isResponseJson;

          try {
            const rqst = request(req);
            if (io.socketVersion === 1) {
              emit(rqst);
            }
            else {
              rqst
                .on('error', e => logger.error('received error receiving data from target', e))
                .on('response', (response) => {
                  logger.debug("Response received - steaming to Server over WebSockets");
                  const status = (response && response.statusCode) || 500;
                  logResponse(logContext, status, response, config);
                  isResponseJson = isJson(response.headers);
                  const ioData = JSON.stringify({
                    status,
                    headers: response.headers
                  });
                  const data = new Buffer(37 + ioData.length);
                  data.writeUInt8(constants.MESSAGE_TYPE_HEADERS);
                  data.write(streamingID, 1, 'utf8');
                  data.write(ioData, 37, 'utf8');
                  io.send(data, {binary: true});
                })
                .on('data', (chunk) => {
                  logger.trace("writing data to web socket");
                  if (config.RES_BODY_URL_SUB && isResponseJson) {
                    const {newChunk, partial} = replaceUrlPartialChunk(
                      Buffer.from(chunk).toString(),
                      prevPartialChunk,
                      config,
                    );
                    prevPartialChunk = partial;
                    chunk = newChunk;
                  }
                  const data = new Buffer(37);
                  data.writeUInt8(constants.MESSAGE_TYPE_DATA);
                  data.write(streamingID, 1, 'utf8');
                  const toWrite = Buffer.concat([data, chunk]);
                  if (io.bufferedAmount > 1048576 && !rqst._paused) {
                    rqst.pause();
                    io.send(toWrite, {binary: true}, () => {
                      logger.trace('resuming request stream');
                      rqst.resume();
                    });
                  } else {
                    io.send(toWrite, {binary: true});
                  }
                })
                .on('end', () => {
                  logger.debug("writing end to WebSocket");
                  const data = new Buffer(37);
                  data.writeUInt8(constants.MESSAGE_TYPE_EOF);
                  data.write(streamingID, 1, 'utf8');
                  io.send(data, {binary: true});
                });
            }
          } catch(e) {
            logger.error(e);
          }
          return;
        }

        request(req, (error, response, responseBody) => {
          if (error) {
            logError(logContext, error);
            return emit({
              status: 500,
              body: error.message,
            });
          }

          const contentLength = responseBody.length;
          // Note that the other side of the request will also check the length and will also reject it if it's too large
          // Set to 20MB even though the server is 21MB because the server looks at the total data travelling through the websocket,
          // not just the size of the body, so allow 1MB for miscellaneous data (e.g., headers, Primus overhead)
          const maxLength = parseInt(config.socketMaxResponseLength) || 20971520;
          if (contentLength && contentLength > maxLength) {
            const errorMessage = `body size of ${contentLength} is greater than max allowed of ${maxLength} bytes`;
            logError(logContext, {
              errorMessage
            });
            return emit({
              status: 502,
              errorType: 'BODY_TOO_LARGE',
              originalBodySize: contentLength,
              body: {
                message: errorMessage
              }
            })
          }

          const status = (response && response.statusCode) || 500;
          if (config.RES_BODY_URL_SUB && isJson(response.headers)) {
            const replaced = replaceUrlPartialChunk(responseBody, null, config);
            responseBody = replaced.newChunk;
          }
          logResponse(logContext, status, response, config);
          emit({ status, body: responseBody, headers: response.headers });
        });
      });
    };
}

function isJson(responseHeaders) {
  return responseHeaders['content-type']
    ? responseHeaders['content-type'].includes('json')
    : false;
}

function logResponse(logContext, status, response, config = null) {
  logContext.httpStatus = status;
  logContext.httpHeaders = response.headers;
  logContext.httpBody =
    config && config.LOG_ENABLE_BODY === 'true' ? response.body : null;

  logger.info(logContext, 'sending response back to websocket connection');
}

function logError(logContext, error) {
  logContext.error = error;
  logger.error(
    logContext,
    'error while sending websocket request over HTTP connection',
  );
}
