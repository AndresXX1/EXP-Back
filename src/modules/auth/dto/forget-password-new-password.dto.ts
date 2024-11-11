import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgetPasswordNewPasswordDto {
  @IsString()
  @IsNotEmpty({ message: 'Introduce un token.' })
  token: string;

  @IsString()
  @IsNotEmpty({ message: 'Introduce un codigo.' })
  code: string;

  @ApiProperty({ example: '123456', description: 'Password' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce una Contraseña.' })
  password: string;

  @ApiProperty({ example: '123456', description: 'ConfirmPassword' })
  @IsString()
  @IsNotEmpty({ message: 'Confirma tu Contraseña.' })
  confirmPassword: string;
}
