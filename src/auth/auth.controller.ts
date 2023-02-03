import {
  Controller,
  Post,
  Body,
  Req,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { CurrentUser, Public } from './common/decorators';
import { RtGuard } from './common/guards';
import { AuthDto } from './dtos';
import { Token } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('/local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() body: AuthDto): Promise<Token> {
    return this.authService.signupLocal(body);
  }

  @Public()
  @Post('/local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() body: AuthDto): Promise<Token> {
    return this.authService.signinLocal(body);
  }

  @Post('/local/logout')
  @HttpCode(HttpStatus.OK)
  logout(@CurrentUser('sub') userId: number) {
    console.log(userId);
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('/local/refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(@Req() req: Request) {
    const userId = req.user['sub'];
    const rt = req.user['refreshToken'];
    return this.authService.refreshToken(userId, rt);
  }
}
