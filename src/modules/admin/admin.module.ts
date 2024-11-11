import { forwardRef, Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Admin } from '../../models/Admin.entity';
import { AdminService } from './admin.service';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SessionAdmin } from '@models/SessionAdmin.entity';
import { EmailService } from './email.service';
import { UserModule } from '@modules/user/user.module';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('access_token.secret'),
        signOptions: {
          expiresIn: config.get<string>('access_token.expiresIn'),
        },
      }),
    }),
    TypeOrmModule.forFeature([Admin, SessionAdmin]),
    forwardRef(() => UserModule),
  ],
  providers: [AdminService, JwtService, ConfigService, EmailService],
  controllers: [AdminController],
  exports: [AdminService, EmailService],
})
export class AdminModule {}
