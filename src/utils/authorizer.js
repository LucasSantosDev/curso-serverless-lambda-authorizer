const SecretsManager = require('./secretsManager')

module.exports.getToken = (headers, headersFieldName) => {
  if (!headers[headersFieldName]) {
    throw new Error('Missing header basic authorization')
  }

  return headers[headersFieldName].replace('Basic ', '')
}

module.exports.tokenIsValid = async (
  token,
  clientIDName,
  clientPasswordName,
) => {
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

module.exports.nextHandle = (resource) => {
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

module.exports.unAuthorized = () => {
  return 'Unauthorized'
}
