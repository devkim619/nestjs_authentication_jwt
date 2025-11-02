import { Injectable, InternalServerErrorException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { UsersService } from '../users/users.service'
import {
  RefreshTokenExpiredException,
  RefreshTokenReusedException,
  RefreshTokenRevokedException,
} from './exceptions/auth.exceptions'
import { RefreshTokenRepository } from './repositories/refresh-token.repository'
import { comparePassword } from './utils/bcrypt.util'
import { RequestMetadata } from './utils/request-meta.util'
import { signAccessToken, type UserInfo } from './utils/token.util'

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
    private readonly tokenRepo: RefreshTokenRepository,
  ) {}

  /**
   * Validate user credentials (Business Logic)
   */
  async validateUser(
    email: string,
    password: string,
  ): Promise<{ id: string; email: string; displayName?: string } | null> {
    try {
      const user = await this.users.findByEmail(email)
      if (!user) return null

      const isValid = await comparePassword(password, user.passwordHash)
      return isValid
        ? { id: user.id, email: user.email, displayName: user.displayName }
        : null
    } catch (_error) {
      throw new InternalServerErrorException('Failed to validate user')
    }
  }

  /**
   * Issue new access and refresh tokens (Business Logic)
   */
  async issueTokens(
    user: UserInfo,
    meta?: RequestMetadata,
  ): Promise<{
    access_token: string
    refresh_token: string
    refresh_token_id: string
  }> {
    try {
      const access_token = signAccessToken(this.jwt, user)
      const refresh_token = this.tokenRepo.createRefreshToken(user)
      const saved = await this.tokenRepo.save(user.id, refresh_token, meta)

      return {
        access_token,
        refresh_token,
        refresh_token_id: saved.id,
      }
    } catch (_error) {
      throw new InternalServerErrorException('Failed to issue tokens')
    }
  }

  /**
   * Refresh tokens using a refresh token (Business Logic)
   */
  async refresh(
    rawRefreshToken: string,
    meta?: RequestMetadata,
  ): Promise<{
    access_token: string
    refresh_token: string
    refresh_token_id: string
  }> {
    try {
      // 1) Verify signature & expiration
      const payload = await this.tokenRepo.verifyRefreshToken(rawRefreshToken)

      // 2) Find user's refresh tokens
      const tokens = await this.tokenRepo.findByUserId(payload.sub)

      // 3) Check for token reuse
      const matched = await this.tokenRepo.findMatchedToken(
        tokens,
        rawRefreshToken,
      )
      if (!matched) {
        // Reuse detection: revoke all tokens for security
        await this.tokenRepo.revokeAllForUser(payload.sub)
        throw new RefreshTokenReusedException()
      }

      // 4) Check token status
      if (matched.revokedAt) {
        throw new RefreshTokenRevokedException()
      }

      if (matched.expiresAt.getTime() <= Date.now()) {
        await this.tokenRepo.revoke(matched.id)
        throw new RefreshTokenExpiredException()
      }

      // 5) Rotate: issue new tokens and revoke old one
      // Fetch fresh user data to get displayName
      const userData = await this.users.findByEmail(payload.email)
      const user: UserInfo = {
        id: payload.sub,
        email: payload.email,
        displayName: userData?.displayName,
      }

      const access_token = signAccessToken(this.jwt, user)
      const refresh_token = this.tokenRepo.createRefreshToken(user)
      const saved = await this.tokenRepo.save(user.id, refresh_token, meta)

      await this.tokenRepo.markAsReplaced(matched.id, saved.id)

      return {
        access_token,
        refresh_token,
        refresh_token_id: saved.id,
      }
    } catch (error) {
      // Re-throw known exceptions
      if (
        error instanceof RefreshTokenReusedException ||
        error instanceof RefreshTokenRevokedException ||
        error instanceof RefreshTokenExpiredException
      ) {
        throw error
      }
      throw new InternalServerErrorException('Failed to refresh tokens')
    }
  }

  /**
   * Logout by revoking the refresh token (Business Logic)
   */
  async logout(rawRefreshToken: string): Promise<{ ok: boolean }> {
    try {
      const tokens = await this.tokenRepo.findAll(500)
      const matched = await this.tokenRepo.findMatchedToken(
        tokens,
        rawRefreshToken,
      )

      if (matched) {
        await this.tokenRepo.revoke(matched.id)
      }

      return { ok: true }
    } catch (_error) {
      throw new InternalServerErrorException('Failed to logout')
    }
  }
}
