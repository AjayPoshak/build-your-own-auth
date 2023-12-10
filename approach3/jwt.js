/**
  * This class generates and validates the JWT tokens.
  *
  * Generally JWT implementations support mulitple algorithms for signing the token, but in our implementation we're limiting it 
  * to RS256 algorithm only. This algo uses public-private key pairs to sign and validate the tokens.
  **/
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import util from 'node:util'

function  base64url(string) {
  return Buffer.from(string, 'utf-8').toString('base64')
}

class JWT {
  constructor(privateKeyFilePath, publicKeyFilePath) {
    if(!privateKeyFilePath) throw new Error('Please pass a valid path to private key file')
    if(!publicKeyFilePath) throw new Error('Please pass a valid path to public key file')
    this.#readPublicKey(publicKeyFilePath)
    this.#readPrivateKey(privateKeyFilePath)
  }

  #readPublicKey(publicKeyFilePath) {
    this.publicKey = fs.readFileSync(new URL(publicKeyFilePath, import.meta.url).pathname, 'utf-8')
  }

  #readPrivateKey(privateKeyFilePath) {
    this.privateKey = fs.readFileSync(new URL(privateKeyFilePath, import.meta.url).pathname, 'utf-8')
  }

  sign(payload, algo, expiry) {
    if(!this.privateKey) throw new Error('Please pass valid private key in constructor')
    const header = {
      alg: 'RS256', // This implementation only supports RS256
      typ: 'JWT',
      kid: '',
    }

    try {
      const privateKeyObject = crypto.createPrivateKey(this.privateKey)
      if(privateKeyObject.type !== 'private') {
        throw new Error('For RS256 algo, passed private key must be asymmetric key') // Asymmetric key means only the issuer can have private key
      }
     const encodedHeader = base64url(JSON.stringify(header), 'binary')
     const encodedPayload = base64url(JSON.stringify(payload), 'utf-8')
     const input = util.format('%s.%s', encodedHeader, encodedPayload)
     const signer = crypto.createSign('RSA-SHA256')
     signer.update(input)
     const signature = signer.sign(privateKeyObject, 'base64')
      return util.format('%s.%s', input, signature)
    } catch(err) {
      console.error('Secret key is not valid material ', err)
    }
 }

  verify(jwtString) {
    if(!this.publicKey) throw new Error('Please pass valid public key in constructor')
    const [headerString, payloadString, signatureString] = jwtString.split('.')
    console.log({headerString, payloadString, signatureString})
    const verifier = crypto.createVerify('RSA-SHA256')
    verifier.update(headerString+'.'+payloadString)
    const isVerified = verifier.verify(this.publicKey, signatureString, 'base64')
    return isVerified
  }

  decode(jwtString) {
    if(!jwtString && jwtString.split('.').length !== 3) throw new Error('Please pass a valid string')
    const [headerString, payloadString, signatureString] = jwtString.split('.')
    const header = JSON.parse(Buffer.from(headerString, 'base64').toString())
    if(!header) return null
    const decodedPayload = Buffer.from(payloadString, 'base64').toString()
    let payload = decodedPayload
    if(header.typ === 'JWT') payload = JSON.parse(decodedPayload)
    return {
      header,
      payload,
      signature: signatureString
    }
  }
}

const jwt = new JWT('../private_key.pem', '../public_key.pem')
const token = jwt.sign({email: 'user1@gmail.com'})
console.log('=====> is token valid ', jwt.verify(token))
console.log('=====> decoded token ', jwt.decode(token))
