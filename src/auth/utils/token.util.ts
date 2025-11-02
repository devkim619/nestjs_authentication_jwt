import { UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import type { StringValue } from 'ms'

export interface TokenPayload {
  sub: string
  email: string
  displayName?: string
  typ?: string
}

export interface UserInfo {
  id: string
  email: string
  displayName?: string
}

export const signAccessToken = (
  jwtService: JwtService,
  user: UserInfo,
): string => {
  try {
    return jwtService.sign({
      sub: user.id,
      email: user.email,
      displayName: user.displayName,
    })
  } catch (_error) {
    throw new UnauthorizedException('Failed to sign access token')
  }
}

export const signRefreshToken = (
  jwtService: JwtService,
  user: UserInfo,
  secret: string,
  expiresIn: StringValue = '7d',
): string => {
  try {
    return jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        displayName: user.displayName,
        typ: 'refresh',
      },
      { secret, expiresIn },
    )
  } catch (_error) {
    throw new UnauthorizedException('Failed to sign refresh token')
  }
}

export const verifyRefreshToken = async (
  jwtService: JwtService,
  token: string,
  secret: string,
): Promise<TokenPayload> => {
  try {
    return await jwtService.verifyAsync<TokenPayload>(token, { secret })
  } catch (_error) {
    throw new UnauthorizedException('Invalid or expired refresh token')
  }
}

export const decodeToken = (jwtService: JwtService, token: string): any => {
  try {
    return jwtService.decode(token)
  } catch (_error) {
    throw new UnauthorizedException('Failed to decode token')
  }
}

export const extractTokenExpiration = (decodedToken: any): number => {
  if (decodedToken?.exp && typeof decodedToken.exp === 'number') {
    return decodedToken.exp
  }
  // Default to 7 days from now if no exp claim
  return Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7
}
