import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { join } from 'path';
import { AppService } from './app.service';
import { DataService } from './scripts/DataService';
import { ConfigService } from '@nestjs/config';
import { ServeStaticModule } from '@nestjs/serve-static';
import { ConfigModuleOptions } from './config/options';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from '@modules/user/user.module';
import { AuthModule } from '@modules/auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AdminModule } from '@modules/admin/admin.module';
import { ScheduleModule } from '@nestjs/schedule';

@Module({
  imports: [
    ConfigModule.forRoot(ConfigModuleOptions),
    ScheduleModule.forRoot(),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', '..', 'uploads', 'avatar'),
      serveRoot: '/avatar',
    }),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', '..', 'uploads', 'assets'),
      serveRoot: '/assets',
    }),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', '..', 'uploads', 'banner'),
      serveRoot: '/banner',
    }),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', '..', 'uploads', 'notice'),
      serveRoot: '/notice',
    }),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', '..', 'uploads', 'branch'),
      serveRoot: '/branch',
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('database.host'),
        port: configService.get<number | undefined>('database.port'),
        username: configService.get<string>('database.user'),
        password: configService.get<string>('database.pass'),
        database: configService.get<string>('database.name'),
        entities: [join(__dirname, '**', '*.entity.{ts,js}')],
        synchronize: true,
        force: true,
      }),
    }),
    UserModule,
    AuthModule,
    AdminModule,
  ],
  controllers: [AppController],
  providers: [AppService, DataService],
})
export class AppModule {}
