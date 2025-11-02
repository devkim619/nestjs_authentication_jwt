import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  InternalServerErrorException,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common'
import { Request, Response } from 'express'
import {
  ApiResponse,
  createSuccessResponse,
} from '../common/dto/api-response.dto'
import {
  COOKIE_NAMES,
  getClearRefreshTokenCookieOptions,
  getRefreshTokenCookieOptions,
} from '../config/cookie.config'
import { UsersService } from '../users/users.service'
import { AuthService } from './auth.service'
import {
  AuthResponseData,
  LogoutResponseData,
  RefreshResponseData,
} from './dto/auth-response.dto'
import { JwtAuthGuard } from './guards/jwt-auth.guard'
import { LocalAuthGuard } from './guards/local-auth.guard'
import { extractRequestMetadata } from './utils/request-meta.util'

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly users: UsersService,
  ) {}

  /**
   * Register a new user and issue tokens
   * Refresh token is sent via HttpOnly cookie
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(
    @Body() dto: { email: string; password: string; displayName?: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<AuthResponseData>> {
    try {
      const user = await this.users.createUser(
        dto.email,
        dto.password,
        dto.displayName,
      )

      const meta = extractRequestMetadata(req)
      const tokens = await this.auth.issueTokens(
        { id: user.id, email: user.email },
        meta,
      )

      // Send refresh token via HttpOnly cookie
      res.cookie(
        COOKIE_NAMES.REFRESH_TOKEN,
        tokens.refresh_token,
        getRefreshTokenCookieOptions(),
      )

      const responseData: AuthResponseData = {
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
        },
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        refresh_token_id: tokens.refresh_token_id,
      }

      return createSuccessResponse(
        responseData,
        'User registered successfully',
        HttpStatus.CREATED,
      )
    } catch (_error) {
      throw new InternalServerErrorException('Failed to register user')
    }
  }

  /**
   * Login with email and password
   * Refresh token is sent via HttpOnly cookie
   */
  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Req() req: any,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<AuthResponseData>> {
    try {
      const meta = extractRequestMetadata(req)
      const tokens = await this.auth.issueTokens(
        { id: req.user.id, email: req.user.email },
        meta,
      )

      // Send refresh token via HttpOnly cookie
      res.cookie(
        COOKIE_NAMES.REFRESH_TOKEN,
        tokens.refresh_token,
        getRefreshTokenCookieOptions(),
      )

      const responseData: AuthResponseData = {
        user: {
          id: req.user.id,
          email: req.user.email,
          displayName: req.user.displayName,
        },
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        refresh_token_id: tokens.refresh_token_id,
      }

      return createSuccessResponse(responseData, 'Login successful')
    } catch (_error) {
      throw new InternalServerErrorException('Failed to login')
    }
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<RefreshResponseData>> {
    try {
      // Get refresh token from cookie
      const refreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN]

      if (!refreshToken) {
        throw new InternalServerErrorException('Refresh token not found')
      }

      const meta = extractRequestMetadata(req)
      const tokens = await this.auth.refresh(refreshToken, meta)

      // Send new refresh token via HttpOnly cookie
      res.cookie(
        COOKIE_NAMES.REFRESH_TOKEN,
        tokens.refresh_token,
        getRefreshTokenCookieOptions(),
      )

      const responseData: RefreshResponseData = {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        refresh_token_id: tokens.refresh_token_id,
      }

      return createSuccessResponse(responseData, 'Token refreshed successfully')
    } catch (error) {
      // Re-throw auth exceptions as-is
      if (
        error instanceof Error &&
        (error.name === 'UnauthorizedException' ||
          error.message.includes('token'))
      ) {
        throw error
      }
      throw new InternalServerErrorException('Failed to refresh token')
    }
  }

  /**
   * Logout by revoking refresh token from cookie
   * Clears the refresh token cookie
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiResponse<LogoutResponseData>> {
    try {
      // Get refresh token from cookie
      const refreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN]

      if (refreshToken) {
        await this.auth.logout(refreshToken)
      }

      // Clear refresh token cookie
      res.cookie(
        COOKIE_NAMES.REFRESH_TOKEN,
        '',
        getClearRefreshTokenCookieOptions(),
      )

      const responseData: LogoutResponseData = { ok: true }

      return createSuccessResponse(responseData, 'Logout successful')
    } catch (_error) {
      throw new InternalServerErrorException('Failed to logout')
    }
  }

  /**
   * Get current user information
   */
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @HttpCode(HttpStatus.OK)
  me(@Req() req: any): ApiResponse {
    return createSuccessResponse({ user: req.user }, 'Requst Successful')
  }
}
