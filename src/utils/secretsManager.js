'use strict'

const AWS = require('aws-sdk')

module.exports = class SecretsManager {
  constructor(region = null) {
    this.client = new AWS.SecretsManager({
      region: region ?? 'us-east-1',
    })
  }

  async getSecret(envVarName) {
    const envName = String(envVarName).toUpperCase()
    const secret = process.env[envName]

    if (secret) {
      console.log('Secret was in the cache')
      return secret
    }

    const { SecretString } = await this.client
      .getSecretValue({
        SecretId: envVarName,
      })
      .promise()

    console.log('Secret was fetched from secrets manager')

    process.env[envName] = SecretString

    return SecretString
  }
}
