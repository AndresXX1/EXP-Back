import {
  Body,
  Controller,
  Delete,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Post,
  Put,
  Req,
  SetMetadata,
  UnsupportedMediaTypeException,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { AdminService } from './admin.service';
import { Public } from '@infrastructure/decorators/public-route.decorator';
import { LogInDto } from './dto/log-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthRolesGuard } from '@modules/auth/guards/jwt-auth-roles.guard';
import { GetAdmin } from '@infrastructure/decorators/get-user.decorator';
import { META_ROLES } from '@infrastructure/constants';
import { Admin, RoleAdminType } from '@models/Admin.entity';
import * as uuid from 'uuid';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { CreateAdminDto } from './dto/create-admin.dto';
import { FullNameDto } from './dto/full-name.dto';
import { PasswordDto } from './dto/password.dto';
import { UserService } from '@modules/user/user.service';
import { TimerService } from '@modules/timer/timer.service';

const allowedFileExtensions = ['png', 'jpg', 'jpeg', 'gif', 'webp'];

@Controller('admin')
@ApiTags('admin')
export class AdminController {
  constructor(
    private readonly adminService: AdminService,
    private readonly userService: UserService,
    private readonly timerService: TimerService,
  ) {}

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.ADMIN, RoleAdminType.SUPER_ADMIN])
  @ApiOperation({ summary: 'Obtiene tu datos de usuario admins' })
  @ApiBearerAuth()
  @Get('')
  async getProfile(@GetAdmin() admin: Admin) {
    return { ok: true, user: admin };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.ADMIN, RoleAdminType.SUPER_ADMIN])
  @ApiOperation({ summary: 'Obtiene datos de dashboard' })
  @ApiBearerAuth()
  @Get('data')
  async getdata() {
    const age = await this.userService.getAgeStatistics();
    const activeUsersTheseWeek = await this.userService.getActiveUsersCountLastWeek();
    const gender = await this.userService.getGenderStats();
    const timers = await this.timerService.getTimers();
    return {
      ok: true,
      dashboard: {
        usage_time: {
          last_week: 0,
          these_week: 0,
        },
        active_users: {
          these_week: activeUsersTheseWeek,
        },
        age,
        gender,
        created_users: [10, 9, 8, 7, 6, 5, 4, 3],
        timers,
      },
    };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.ADMIN, RoleAdminType.SUPER_ADMIN])
  @ApiOperation({ summary: 'Obtiene todos los admins' })
  @ApiBearerAuth()
  @Get('all')
  async getAdmins() {
    const admins = await this.adminService.getAdmins();
    return { ok: true, admins };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.SUPER_ADMIN])
  @ApiOperation({ summary: 'elimina un admin, solo super admin' })
  @ApiBearerAuth()
  @Delete('remove/:id')
  async deleteBanner(@Param('id') id: string) {
    const adminId = parseInt(`${id}`, 10);
    const adminDeleted = await this.adminService.deleteAdmin(adminId);
    return { ok: true, admin: adminDeleted };
  }

  @Public()
  @ApiBody({ type: LogInDto })
  @ApiOperation({ summary: 'Logea el admin con email y password' })
  @Post('/log-in')
  async logIn(
    @Body() logInDto: LogInDto,
    @Req()
    request: Request,
  ) {
    const userResponse = await this.adminService.logIn(request, logInDto);
    return userResponse;
  }

  @Public()
  @ApiBody({ type: RefreshTokenDto })
  @ApiOperation({ summary: 'Refresca el token' })
  @Post('/refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    const token = await this.adminService.refreshToken(refreshTokenDto);
    return { ok: true, token };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.ADMIN, RoleAdminType.SUPER_ADMIN])
  @Post('/avatar')
  @ApiOperation({ summary: 'subir imagen de avatar, solo admin' })
  @UseInterceptors(
    FileInterceptor('file', {
      fileFilter(req, file, callback) {
        if (!allowedFileExtensions.includes(file.originalname.split('.').pop() ?? '')) {
          return callback(new UnsupportedMediaTypeException(), false);
        }
        callback(null, true);
      },
      storage: diskStorage({
        destination: './uploads/avatar/',
        filename: (req, file, callback) => {
          const uniqueSuffix = uuid.v4();
          const extension = file.originalname.split('.').pop();
          const uniqueFilename = `${uniqueSuffix}.${extension}`;
          callback(null, uniqueFilename);
        },
      }),
    }),
  )
  async uploadFile(
    @UploadedFile()
    file: Express.Multer.File,
  ) {
    if (!file) throw new HttpException('a file is required', HttpStatus.BAD_REQUEST);
    const avatarName = file.filename;
    return { ok: true, avatar: avatarName };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.ADMIN, RoleAdminType.SUPER_ADMIN])
  @Put('/avatar')
  @ApiOperation({ summary: 'actualizar imagen de tu avatar, solo admin' })
  @UseInterceptors(
    FileInterceptor('file', {
      fileFilter(req, file, callback) {
        if (!allowedFileExtensions.includes(file.originalname.split('.').pop() ?? '')) {
          return callback(new UnsupportedMediaTypeException(), false);
        }
        callback(null, true);
      },
      storage: diskStorage({
        destination: './uploads/avatar/',
        filename: (req, file, callback) => {
          const uniqueSuffix = uuid.v4();
          const extension = file.originalname.split('.').pop();
          const uniqueFilename = `${uniqueSuffix}.${extension}`;
          callback(null, uniqueFilename);
        },
      }),
    }),
  )
  async updateFile(
    @UploadedFile()
    file: Express.Multer.File,
    @GetAdmin() admin: Admin,
  ) {
    if (!file) throw new HttpException('a file is required', HttpStatus.BAD_REQUEST);
    const adminUpdate = await this.adminService.updateAvatar(admin.id, file.filename);
    return { ok: true, user: adminUpdate };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.ADMIN, RoleAdminType.SUPER_ADMIN])
  @Delete('/avatar')
  @ApiOperation({ summary: 'eliminar imagen de tu avatar, solo admin' })
  async deleteAvatar(@GetAdmin() admin: Admin) {
    const adminUpdate = await this.adminService.deleteAvatar(admin.id);
    return { ok: true, user: adminUpdate };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.SUPER_ADMIN])
  @ApiOperation({ summary: 'crear admin, solo super admin' })
  @Post('create')
  async createUserDemo(@Body() createAdminDto: CreateAdminDto) {
    const admin = await this.adminService.createAdminFetch(createAdminDto);
    return { ok: true, admin };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.SUPER_ADMIN])
  @ApiOperation({ summary: 'actualizar nombre completo, solo super admin' })
  @Put('full-name')
  async updateFullName(@GetAdmin() admin: Admin, @Body() fullNameDto: FullNameDto) {
    const adminUpdated = await this.adminService.updateFullName(admin.id, fullNameDto.full_name);
    return { ok: true, user: adminUpdated };
  }

  @UseGuards(JwtAuthRolesGuard)
  @SetMetadata(META_ROLES, [RoleAdminType.SUPER_ADMIN])
  @ApiOperation({ summary: 'actualizar password, solo super admin' })
  @Put('password')
  async updatePassword(@GetAdmin() admin: Admin, @Body() passwordDto: PasswordDto) {
    const adminUpdated = await this.adminService.updatePassword(admin.id, passwordDto.password, passwordDto.new_password);
    return { ok: true, user: adminUpdated };
  }
}
