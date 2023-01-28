import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import { AuthDto } from './dtos';
import { Token } from './types';
import { ForbiddenException } from '@nestjs/common/exceptions/forbidden.exception';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signupLocal(body: AuthDto): Promise<Token> {
    const hash = await this.hashData(body.password);

    const user = await this.prisma.user.findUnique({
      where: { email: body.email },
    });

    if (user) {
      throw new BadRequestException('Email in use!');
    }

    const newUser = await this.prisma.user.create({
      data: {
        email: body.email,
        hash,
      },
    });

    const tokens = await this.signToken(newUser.id, newUser.email);
    await this.updateRT(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(body: AuthDto) {
    const user = await this.prisma.user.findFirst({
      where: { email: body.email },
    });

    if (!user) {
      throw new BadRequestException('Email not found');
    }

    const IsPwMatch = await bcrypt.compare(body.password, user.hash);

    if (!IsPwMatch) {
      console.log(IsPwMatch);
      throw new BadRequestException('Incroct password');
    }

    const tokens = await this.signToken(user.id, user.email);
    await this.updateRT(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refreshToken(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access Denied');
    }

    const isRtMatch = await bcrypt.compare(rt, user.hashedRt);
    if (!isRtMatch) throw new ForbiddenException('Access Denied token');

    const tokens = await this.signToken(user.id, user.email);
    await this.updateRT(user.id, tokens.refresh_token);
    return tokens;
  }

  // **HRLPER FUNCTIONS
  //* Helper function */ Hash data
  private hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  //* Helper function */ Genarate Token
  private async signToken(userId: number, email: string): Promise<Token> {
    const [at, rt] = await Promise.all([
      this.jwt.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15,
        },
      ),
      this.jwt.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 15 * 24 * 7,
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  //* Helper function */ save the token to the data base
  private async updateRT(userId: number, rt: string) {
    // hash the rt
    const hashRt = await this.hashData(rt);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        hashedRt: hashRt,
      },
    });
  }
}
