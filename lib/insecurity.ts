/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'fs'
import crypto from 'crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = process.env.JWT_PRIVATE_KEY || '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

// [Rest of the code remains unchanged]
export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: any) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
