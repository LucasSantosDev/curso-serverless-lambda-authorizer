const SecretsManager = require('../utils/secretsManager')

const getToken = (headers, headersFieldName) => {
  if (!headers[headersFieldName]) {
    throw new Error('Missing header basic authorization')
  }

  return headers[headersFieldName].replace('Basic ', '')
}

const tokenIsValid = async (token, clientIDName, clientPasswordName) => {
  try {
    const secretManager = new SecretsManager()
    const clientIDSecret = await secretManager.getSecret(clientIDName)
    const clientPasswordSecret = await secretManager.getSecret(
      clientPasswordName,
    )

    if (!clientIDSecret || !clientPasswordName) {
      throw new Error('Missing clientID or password')
    }

    const credentials = Buffer.from(token, 'base64').toString('ascii')
    const [clientID, clientPassword] = credentials.split(':')

    return (
      clientIDSecret === clientID && clientPasswordSecret === clientPassword
    )
  } catch (error) {
    console.error(error)

    return false
  }
}

const nextHandle = (resource) => {
  return {
    principalId: 'user',
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: resource,
        },
      ],
    },
  }
}

const unAuthorized = () => {
  return 'Unauthorized'
}

module.exports.handler = async (event, context, callback) => {
  const { methodArn: resource } = event
  const clientID = process.env.SECRET_AUTHORIZER_CLIENT_ID
  const clientPassword = process.env.SECRET_AUTHORIZER_PASSWORD

  const token = getToken(event, 'authorizationToken')

  const isValid = await tokenIsValid(token, clientID, clientPassword)

  return isValid
    ? callback(null, nextHandle(resource))
    : callback(unAuthorized())
}
