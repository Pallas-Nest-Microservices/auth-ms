import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';

import * as bcrypt from 'bcrypt';

import { PrismaClient } from 'generated/prisma';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  constructor(private readonly jwtService: JwtService) {
    super();
  }

  private readonly logger = new Logger(AuthService.name);

  onModuleInit() {
    this.$connect();
    this.logger.log('Prisma Client connected to the database');
  }

  async signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async registerUser({ name, email, password }: RegisterUserDto) {
    try {
      const registeredUser = await this.user.findUnique({ where: { email } });

      if (registeredUser) {
        throw new RpcException({ status: 400, message: 'User already exists' });
      }

      const newUser = await this.user.create({
        data: {
          name,
          email,
          password: bcrypt.hashSync(password, 10),
        },
      });

      const { password: _, ...userRest } = newUser;
      const token = await this.signJwt(userRest);

      return { user: userRest, token };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser({ email, password }: LoginUserDto) {
    try {
      const user = await this.user.findUnique({ where: { email } });

      if (!user) {
        throw new RpcException({ status: 404, message: 'User not found' });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({ status: 400, message: 'Invalid password' });
      }

      const { password: _, ...userRest } = user;
      const token = await this.signJwt(userRest);

      return { user: userRest, token };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async verifyUser(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return { user, token: await this.signJwt(user) };
    } catch (err) {
      throw new RpcException({ status: 400, message: 'Invalid token' });
    }
  }
}
