// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { User } from './schemas/user.schema';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(payload: JwtPayload): Promise<User> {
    return this.userModel.findOne({ username: payload.username }).exec();
  }

  async register(username: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({ username, password: hashedPassword });
    return newUser.save();
  }

  async login(username: string, password: string): Promise<{ accessToken: string }> {
    const user = await this.userModel.findOne({ username }).exec();
    if (user && await bcrypt.compare(password, user.password)) {
      const payload: JwtPayload = { username: user.username, role: user.role };
      const accessToken = this.jwtService.sign(payload);
      return { accessToken };
    }
    throw new UnauthorizedException('Invalid credentials');
  }
}
