module.exports.handler = async (event, context, callback) => {
  const { methodArn: resource } = event
  const clientID = process.env.SECRET_AUTHORIZER_CLIENT_ID
  const clientPassword = process.env.SECRET_AUTHORIZER_PASSWORD

  const token = getToken(event, 'authorization')

  const isValid = await tokenIsValid(token, clientID, clientPassword)

  return isValid
    ? callback(null, nextHandle(resource))
    : callback(unAuthorized())
}
