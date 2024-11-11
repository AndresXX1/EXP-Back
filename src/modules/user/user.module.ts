import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../../models/User.entity';
import { UserService } from './user.service';
import { AuthModule } from '../auth/auth.module';
import { AuthService } from '../auth/auth.service';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SessionService } from '@modules/auth/session.service';
import { Session } from '@models/Session.entity';
import { UserController } from './user.controller';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { AdminModule } from '@modules/admin/admin.module';

@Module({
  providers: [UserService, AuthService, JwtService, SessionService],
  controllers: [UserController],
  imports: [
    TypeOrmModule.forFeature([User, Session]),
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('access_token.secret'),
        signOptions: {
          expiresIn: config.get<string>('access_token.expiresIn'),
        },
      }),
    }),
    MailerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        transport: {
          host: configService.get<string>('nodemailer.host'),
          port: configService.get<number>('nodemailer.port'),
          secure: true,
          auth: {
            user: configService.get<string>('nodemailer.username'),
            pass: configService.get<string>('nodemailer.password'),
          },
        },
        defaults: {
          from: configService.get<string>('nodemailer.from'),
        },
        template: {
          dir: process.cwd() + '/template/',
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
      }),
    }),
    forwardRef(() => AuthModule),
    forwardRef(() => AdminModule),
  ],
  exports: [UserService],
})
export class UserModule {}
