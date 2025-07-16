/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import path from 'path'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
const insecurity = require('../lib/insecurity')

const challenges = require('../data/datacache').challenges
const challengeUtils = require('../lib/challengeUtils')
const router = express.Router()

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.get('/', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) {
    next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    return
  }
  const email = loggedInUser.data.email

  try {
    const answer = await SecurityAnswerModel.findOne({
      include: [{
        model: UserModel,
        where: { email }
      }]
    })
    if (answer == null) {
      throw new Error('No answer found!')
    }
    const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
    if (question == null) {
      throw new Error('No question found!')
    }

    res.render('dataErasureForm', { userEmail: email, securityQuestion: question.question })
  } catch (error) {
    next(error)
  }
})

interface DataErasureRequestParams {
  layout?: string
  email: string
  securityAnswer: string
}

// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.post('/', async (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): Promise<void> => {
  const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
  if (!loggedInUser) {
    next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    return
  }

  try {
    await PrivacyRequestModel.create({
      UserId: loggedInUser.data.id,
      deletionRequested: true
    })

    res.clearCookie('token')
    if (req.body.layout) {
      // Validate and sanitize layout input to prevent directory traversal
      const safeLayout = path.basename(req.body.layout)
      
      res.render('dataErasureResult', {
        ...req.body,
        layout: safeLayout
      })
    } else {
      res.render('dataErasureResult', {
        ...req.body
      })
    }
  } catch (error) {
    next(error)
  }
})

export default router