import { BadRequestException, HttpException, HttpStatus, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcrypt';
import axios from 'axios';
import { User } from '../../models/User.entity';
import { Logger } from '@nestjs/common';
import { Session } from '@models/Session.entity';
import { SessionService } from './session.service';
import { ConfigService } from '@nestjs/config';
import { LogInDto } from './dto/log-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LogInWithGoogleDto } from './dto/log-in-with-google.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { ForgetPasswordCodeDto } from './dto/forget-password-code.dto';
import { MailerService } from '@nestjs-modules/mailer';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { ForgetPasswordNewPasswordDto } from './dto/forget-password-new-password.dto';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

export class validatedSession {
  user: User;
  sessionId: number;
}

export class validatedSessionToken {
  user?: User;
  sessionId?: number;
  isValidToken: boolean;
}

export class GoogleUser {
  email: string;
}

class AccessRefreshTokenGenerated {
  session: Session;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly userService: UserService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly sessionService: SessionService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  async logIn(req, logInDto: LogInDto) {
    const user = await this.userService.userExistByEmail(logInDto.email);

    if (!user) {
      throw new NotFoundException('El usuario no existe.');
    }

    const userPassword = await this.userService.findByEmailWithPassword(logInDto.email);

    if (!bcrypt.compareSync(logInDto.password, userPassword)) {
      throw new UnauthorizedException('Contraseña no válida.');
    }

    await this.userService.updateLastLogin(user, logInDto.tokenNotifications);

    const { refreshToken, session } = await this.generateAccessRefreshToken(req, user);

    const token = await this.generateAccessToken(user.id, session.id);

    return {
      ok: true,
      token,
      refreshToken,
    };
  }

  async logInWithGoogle(req, logInWithGoogleDto: LogInWithGoogleDto) {
    // Conectarse a la API de Google con el token
    const googleUser = await this.getUserWithGoogleTokens(logInWithGoogleDto.token);

    const user = await this.userService.userExistByEmail(googleUser.email);

    if (!user) {
      const userCreated = await this.userService.createWithGoogle(googleUser.email);

      await this.userService.updateLastLogin(userCreated, logInWithGoogleDto.tokenNotifications);

      const { refreshToken, session } = await this.generateAccessRefreshToken(req, userCreated);

      const token = await this.generateAccessToken(userCreated.id, session.id);

      return {
        ok: true,
        token,
        refreshToken,
      };
    }

    await this.userService.updateLastLogin(user, logInWithGoogleDto.tokenNotifications);

    const { refreshToken, session } = await this.generateAccessRefreshToken(req, user);

    const token = await this.generateAccessToken(user.id, session.id);

    return {
      ok: true,
      token,
      refreshToken,
    };
  }

  async generateAccessRefreshToken(req, user: User): Promise<AccessRefreshTokenGenerated> {
    const session = await this.sessionService.createSession(req, user);

    const payload = { userId: user.id, sessionId: session.id };

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('session.secretKeyRefresh'),
      expiresIn: this.configService.get<string>('session.jwtTokenRefreshExpiration'),
    });

    return { refreshToken, session };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<string> {
    const refreshTokenData = await this.validateAccessRefreshToken(refreshTokenDto.refresh_token);

    if (!refreshTokenData) {
      throw new UnauthorizedException({
        message: 'Refresh token no valido',
      });
    }

    const session = await this.sessionService.findById(refreshTokenData.sessionId);

    if (!session) {
      throw new UnauthorizedException({
        message: 'Unauthorized',
      });
    }

    const payload = {
      userId: refreshTokenData.userId,
      sessionId: refreshTokenData.sessionId,
    };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('session.secretKey'),
      expiresIn: this.configService.get<string>('session.jwtTokenExpiration'),
    });

    return accessToken;
  }

  async removeSession(userId, sessionId): Promise<void> {
    await this.sessionService.removeByIds(userId, sessionId);
  }

  async getSessions(userId): Promise<Session[]> {
    return await this.sessionService.getSessionsByUserId(userId);
  }

  async generateAccessToken(userId, sessionId): Promise<string> {
    const payload = { userId: userId, sessionId: sessionId };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('session.secretKey'),
      expiresIn: this.configService.get<string>('session.jwtTokenExpiration'),
    });

    return accessToken;
  }

  async validateSession(accessToken: string): Promise<validatedSession> {
    if (!accessToken) {
      throw new UnauthorizedException({
        message: 'Token no valido',
      });
    }

    const accessTokenData = await this.validateAccessToken(accessToken);

    if (!accessTokenData) {
      throw new UnauthorizedException({
        message: 'Token no valido',
      });
    }

    const session = await this.sessionService.findByIds(accessTokenData.userId, accessTokenData.sessionId);

    if (!session) {
      throw new UnauthorizedException({
        message: 'Unauthorized',
      });
    }

    const user = await this.userService.findById(accessTokenData.userId);

    return { user: user, sessionId: accessTokenData.sessionId };
  }

  async validateAccessToken(accessToken) {
    try {
      const data = this.jwtService.verify(accessToken, {
        secret: this.configService.get<string>('session.secretKey'),
      });

      return data;
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        throw new UnauthorizedException('El token ha caducado');
      }
      return null;
    }
  }

  async validateAccessTokenSocket(accessToken) {
    try {
      const data = this.jwtService.verify(accessToken, {
        secret: this.configService.get<string>('session.secretKey'),
      });

      return data;
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        return false;
      }
      return false;
    }
  }

  async validateSessionSocket(accessToken: string): Promise<validatedSessionToken> {
    if (!accessToken) {
      return { isValidToken: false };
    }

    const accessTokenData = await this.validateAccessTokenSocket(accessToken);

    if (!accessTokenData) {
      return { isValidToken: false };
    }

    const session = await this.sessionService.findByIds(accessTokenData.userId, accessTokenData.sessionId);

    if (!session) {
      return { isValidToken: false };
    }

    const user = await this.userService.findByIdSocket(accessTokenData.userId);

    if (!user) {
      return { isValidToken: false };
    }

    return { user: user, sessionId: accessTokenData.sessionId, isValidToken: true };
  }

  async validateAccessRefreshToken(refreshToken) {
    try {
      const data = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('session.secretKeyRefresh'),
      });

      return data;
    } catch (e) {
      if (e instanceof TokenExpiredError) {
        throw new UnauthorizedException('El refresh token ha caducado');
      }
    }
  }

  async getUserWithGoogleTokens(accessToken: string): Promise<GoogleUser> {
    try {
      const response = await axios.get('https://www.googleapis.com/userinfo/v2/me', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const user = response.data;
      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid accessToken.');
    }
  }

  async signUp(req, { email, password, tokenNotifications }: CreateUserDto) {
    const userExist = await this.userService.userExistByEmail(email);
    if (userExist) throw new NotFoundException('El usuario ya existe');

    const user = await this.userService.createUser(email, password);

    await this.userService.updateLastLogin(user, tokenNotifications);

    const { refreshToken, session } = await this.generateAccessRefreshToken(req, user);

    const token = await this.generateAccessToken(user.id, session.id);

    return {
      ok: true,
      token,
      refreshToken,
    };
  }

  async resendCode(userId: number) {
    const userExist = await this.userService.findById(userId);

    if (!userExist) {
      throw new NotFoundException('El usuario no existe.');
    }
    const randomNumber = Math.floor(Math.random() * 100000);
    const emailVerificationCode = randomNumber.toString().padStart(5, '0');

    await this.sendEmail(userExist.email, emailVerificationCode);
    userExist.email_code = emailVerificationCode;
    await this.userService.save(userExist);

    return {
      ok: true,
    };
  }

  async verifyEmail(verifyCode: string, userId: number) {
    const userExist = await this.userService.findById(userId, ['email_code']);
    if (!userExist) {
      throw new NotFoundException('El usuario no existe.');
    }
    if (verifyCode !== userExist.email_code) {
      throw new HttpException('Codigo incorrecto.', HttpStatus.BAD_REQUEST);
    }
    await this.userRepository.update(userId, { email_verified: true });
    return {
      ok: true,
    };
  }

  async sendEmail(email: string, code: string) {
    try {
      await this.mailerService.sendMail({
        to: email,
        from: this.configService.get<string>('nodemailer.from'),
        subject: 'ExpressCash: Verifica tu correo electronico',
        template: 'index',
        context: {
          code,
        },
      });
    } catch (error) {
      console.log(error);
    }
  }

  async forgetPassword(forgetPasswordDto: ForgetPasswordDto) {
    const userExist = await this.userService.userExistByEmail(forgetPasswordDto.email);
    if (!userExist) {
      throw new HttpException('Correo electrónico no registrado.', HttpStatus.BAD_REQUEST);
    }
    const randomNumber = Math.floor(Math.random() * 100000);
    const code = randomNumber.toString().padStart(5, '0');
    const payload = { sub: userExist.id, email: userExist.email, code: code };
    const { forgetPasswordToken } = this.generateForgetPasswordToken(payload);

    await this.userService.sendEmail(userExist.email, code);
    return {
      ok: true,
      token: forgetPasswordToken,
    };
  }

  async forgetPasswordCode(forgetPasswordCodeDto: ForgetPasswordCodeDto) {
    const tokenData = await this.validateForgetPasswordToken(forgetPasswordCodeDto.token);
    if (!tokenData) {
      throw new HttpException('Codigo vencido.', HttpStatus.BAD_REQUEST);
    }

    if (tokenData.code !== forgetPasswordCodeDto.code) {
      throw new HttpException('Codigo incorrecto.', HttpStatus.BAD_REQUEST);
    }

    return {
      ok: true,
      code: forgetPasswordCodeDto.code,
    };
  }

  async forgetPasswordNewPassword(forgetPasswordNewPasswordDto: ForgetPasswordNewPasswordDto) {
    const tokenData = await this.validateForgetPasswordToken(forgetPasswordNewPasswordDto.token);
    if (!tokenData) {
      throw new HttpException('Codigo vencido.', HttpStatus.BAD_REQUEST);
    }

    if (tokenData.code !== forgetPasswordNewPasswordDto.code) {
      throw new HttpException('Codigo incorrecto.', HttpStatus.BAD_REQUEST);
    }

    if (forgetPasswordNewPasswordDto.password !== forgetPasswordNewPasswordDto.confirmPassword) {
      throw new BadRequestException('Las contraseñas no coinciden.');
    }

    const userExist = await this.userService.changePassword(tokenData.email, forgetPasswordNewPasswordDto.password);

    if (!userExist) {
      throw new HttpException('Correo electrónico no registrado.', HttpStatus.BAD_REQUEST);
    }

    return {
      ok: true,
    };
  }

  generateForgetPasswordToken(payload) {
    const forgetPasswordToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('forget_password_token.secret'),
      expiresIn: this.configService.get<string>('forget_password_token.expiresIn'),
    });
    return {
      forgetPasswordToken,
    };
  }
  validateForgetPasswordToken(token) {
    try {
      const data = this.jwtService.verify(token, {
        secret: this.configService.get<string>('forget_password_token.secret'),
      });
      return data;
    } catch (e) {
      return null;
    }
  }

  async setNewPassword(newPassword: string, user: User) {
    const savedUser = await this.userService.changePassword(user.email, newPassword);
    if (!savedUser) throw new BadRequestException('Ocurrió un error actualizando los datos');
    return { ok: true, message: 'Contraseña actualizada' };
  }
}
