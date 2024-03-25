import { makeRequestToDownstream } from '../../common/http/request';
import { log as logger } from '../../logs/logger';

export const fetchJwt = async (apiHostname, clientId, clientSecret) => {
  try {
    const data = {
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
    };
    const formData = new URLSearchParams(data);
    const request = {
      url: `${apiHostname}/oauth2/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      body: formData.toString(),
    };
    let oauthResponse = await makeRequestToDownstream(request);
    console.log(oauthResponse);
    if (oauthResponse.statusCode != 200) {
      const errorBody = JSON.parse(oauthResponse.body);
      throw new Error(
        `${oauthResponse.statusCode}-${errorBody.error}:${errorBody.error_description}`,
      );
    }
    const accessToken = JSON.parse(oauthResponse.body);
    let jwt = accessToken.access_token;
    let type = accessToken.token_type;
    let expiresIn = accessToken.expires_in;
    return { expiresIn: expiresIn, authHeader: `${type} ${jwt}` };
  } catch (err) {
    logger.error({ err }, 'Unable to retrieve JWT');
  }
};
