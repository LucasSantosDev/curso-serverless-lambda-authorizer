'use strict'

const {
  tokenIsValid,
  getToken,
  nextHandle,
  unAuthorized,
} = require('../utils/authorizer')

module.exports.handler = async (event, context, callback) => {
  const { routeArn: resource, headers } = event
  const clientID = process.env.SECRET_AUTHORIZER_CLIENT_ID
  const clientPassword = process.env.SECRET_AUTHORIZER_PASSWORD

  const token = getToken(headers, 'authorization')

  const isValid = await tokenIsValid(token, clientID, clientPassword)

  return isValid
    ? callback(null, nextHandle(resource))
    : callback(unAuthorized())
}
