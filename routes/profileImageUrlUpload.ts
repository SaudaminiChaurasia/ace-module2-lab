/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'
import { URL } from 'node:url'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isDisallowedHostname (hostname: string): boolean {
  const lower = hostname.toLowerCase()
  return (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower.endsWith('.arpa') ||
    lower === 'instance-data' ||
    lower === 'metadata.google.internal'
  )
}

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return true
  const [a, b, c] = parts
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a >= 224) return true
  return false
}

function parseIPv6 (ip: string): number[] {
  const normalized = ip.toLowerCase()
  const parts = normalized.split('::')
  const left = parts[0] ? parts[0].split(':') : []
  const right = parts[1] ? parts[1].split(':') : []
  let fullParts: string[]
  if (parts.length > 1) {
    const missing = 8 - (left.length + right.length)
    const middle = new Array(missing).fill('0')
    fullParts = [...left, ...middle, ...right]
  } else {
    fullParts = left
  }
  return fullParts.map(p => parseInt(p, 16) || 0)
}

function isPrivateIPv6 (ip: string): boolean {
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':')
    const ipv4 = ip.substring(lastColon + 1)
    if (net.isIPv4(ipv4)) return isPrivateIPv4(ipv4)
  }
  const words = parseIPv6(ip)
  if (words.length !== 8) return true
  if (words.every(w => w === 0)) return true
  if (words.slice(0, 7).every(w => w === 0) && words[7] === 1) return true
  if (
    (words.slice(0, 5).every(w => w === 0) && (words[5] === 0xffff || words[5] === 0)) ||
    (words[0] === 0x64 && words[1] === 0xff9b && words.slice(2, 6).every(w => w === 0))
  ) {
    const a = words[6] >> 8
    const b = words[6] & 0xff
    const c = words[7] >> 8
    const d = words[7] & 0xff
    return isPrivateIPv4(`${a}.${b}.${c}.${d}`)
  }
  if ((words[0] & 0xfe00) === 0xfc00) return true
  if ((words[0] & 0xffc0) === 0xfe80) return true
  if ((words[0] & 0xff00) === 0xff00) return true
  if (words[0] === 0x2001 && words[1] === 0x0db8) return true
  return false
}

function isPrivateIp (ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip)
  if (net.isIPv6(ip)) return isPrivateIPv6(ip)
  return true
}

async function isSafeUrl (url: string): Promise<boolean> {
  if (typeof url !== 'string' || !url.trim()) return false
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false
  }

  const hostname = parsed.hostname.toLowerCase()
  if (!hostname || isDisallowedHostname(hostname)) {
    return false
  }

  if (parsed.port && !['80', '443', '8080', '8443'].includes(parsed.port)) {
    return false
  }

  const cleanHostname = hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(cleanHostname)) {
    return !isPrivateIp(cleanHostname)
  }

  try {
    const addresses = await dns.lookup(cleanHostname, { all: true })
    if (addresses.some(({ address }) => isPrivateIp(address))) {
      return false
    }
  } catch {
    // DNS resolution failure (e.g. offline in tests); fetch will handle failure
  }

  return true
}

async function fetchSafeUrl (url: string, maxRedirects = 3) {
  let currentUrl = url
  for (let i = 0; i <= maxRedirects; i++) {
    if (!await isSafeUrl(currentUrl)) {
      throw new Error('Blocked illegal activity: unsafe URL')
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('Redirect without location header')
      }
      currentUrl = new URL(location, currentUrl).href
      continue
    }
    return response
  }
  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!await isSafeUrl(url)) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          const response = await fetchSafeUrl(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (utils.getErrorMessage(error).includes('Blocked illegal activity')) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
            return
          }
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
