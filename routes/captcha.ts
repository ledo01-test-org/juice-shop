/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { type Captcha } from '../data/types'
import { CaptchaModel } from '../models/captcha'
import crypto from 'crypto'

function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = crypto.randomInt(1, 11)
    const secondTerm = crypto.randomInt(1, 11)
    const thirdTerm = crypto.randomInt(1, 11)

    const firstOperator = operators[crypto.randomInt(0, 3)]
    const secondOperator = operators[crypto.randomInt(0, 3)]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

captchas.verifyCaptcha = () => (req: Request, res: Response, next: NextFunction) => {
  CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } }).then((captcha: Captcha | null) => {
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  }).catch((error: Error) => {
    next(error)
  })
}

module.exports = captchas
