import { Public } from '@infrastructure/decorators/public-route.decorator';
import { Body, Controller, Delete, Get, Param, Post, Req, UseGuards } from '@nestjs/common';
import { ApiBody, ApiTags, ApiOperation } from '@nestjs/swagger';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GetUser } from '@infrastructure/decorators/get-user.decorator';
import { User } from '@models/User.entity';
import { GetSessionId } from '@infrastructure/decorators/get-session-id.decorator';
import { LogInDto } from './dto/log-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LogInWithGoogleDto } from './dto/log-in-with-google.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { ForgetPasswordCodeDto } from './dto/forget-password-code.dto';
import { ForgetPasswordNewPasswordDto } from './dto/forget-password-new-password.dto';
import { SetPasswordDto } from './dto/set-password.dto';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @ApiBody({ type: LogInDto })
  @ApiOperation({ summary: 'Logea el user con email y password' })
  @Post('/log-in')
  async logIn(
    @Body() logInDto: LogInDto,
    @Req()
    request: Request,
  ) {
    const userResponse = await this.authService.logIn(request, logInDto);
    return userResponse;
  }

  @Public()
  @ApiBody({ type: LogInWithGoogleDto })
  @ApiOperation({ summary: 'Logea el user con token de Google' })
  @Post('/log-in-with-google')
  async logInWithGoogle(
    @Body() logInWithGoogleDto: LogInWithGoogleDto,
    @Req()
    request: Request,
  ) {
    const userResponse = await this.authService.logInWithGoogle(request, logInWithGoogleDto);
    return userResponse;
  }

  @Public()
  @ApiBody({ type: RefreshTokenDto })
  @ApiOperation({ summary: 'Refresca el token' })
  @Post('/refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    const token = await this.authService.refreshToken(refreshTokenDto);
    return { ok: true, token };
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Verifica la cuenta' })
  @Post('/verify-email')
  async verifyEmail(@GetUser() user: User, @Body() { verifyCode }: { verifyCode: string }) {
    const verifyEmailResponse = await this.authService.verifyEmail(verifyCode, user.id);
    return verifyEmailResponse;
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Elimina la session actual del user' })
  @Post('/log-out')
  async getProfile(@GetUser() user: User, @GetSessionId() sessionId: number) {
    await this.authService.removeSession(user.id, sessionId);
    return { ok: true, user, sessionId };
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Obtiene todas las sessions del user' })
  @Get('/session')
  async getSessions(@GetUser() user: User) {
    const sessions = await this.authService.getSessions(user.id);
    return { ok: true, sessions: sessions };
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Elimina una session especifica del user' })
  @Delete('/session/:id')
  async deleteSession(@Param('id') id: number, @GetUser() user: User) {
    await this.authService.removeSession(user.id, id);
    return { ok: true };
  }

  @Public()
  @ApiBody({ type: CreateUserDto })
  @ApiOperation({ summary: 'Crea el user con email y password' })
  @Post('sign-up')
  async createUser(@Req() req: Request, @Body() dto: CreateUserDto) {
    const serviceResponse = await this.authService.signUp(req, dto);

    return serviceResponse;
  }

  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Reenvia codigo al usuario' })
  @Post('/resend-code')
  async resendCode(@GetUser() user: User) {
    const serviceResponse = await this.authService.resendCode(user.id as number);
    return serviceResponse;
  }

  @Public()
  @ApiBody({ type: ForgetPasswordDto })
  @Post('forget-password')
  async forgetPassword(@Body() forgetPasswordDto: ForgetPasswordDto) {
    const userResponse = await this.authService.forgetPassword(forgetPasswordDto);
    return userResponse;
  }

  @Public()
  @ApiBody({ type: ForgetPasswordCodeDto })
  @Post('/forget-password-code')
  async forgetPasswordCode(@Body() forgetPasswordCodeDto: ForgetPasswordCodeDto) {
    const userResponse = await this.authService.forgetPasswordCode(forgetPasswordCodeDto);
    return userResponse;
  }

  @Public()
  @ApiBody({ type: ForgetPasswordNewPasswordDto })
  @Post('/forget-password-new-password')
  async forgetPasswordNewPassword(@Body() forgetPasswordNewPasswordDto: ForgetPasswordNewPasswordDto) {
    const userResponse = await this.authService.forgetPasswordNewPassword(forgetPasswordNewPasswordDto);
    return userResponse;
  }

  @UseGuards(JwtAuthGuard)
  @Post('set-password')
  async setPassword(@GetUser() user: User, @Body() { newPassword }: SetPasswordDto) {
    return await this.authService.setNewPassword(newPassword, user);
  }
}
