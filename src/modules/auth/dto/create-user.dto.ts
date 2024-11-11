import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class CreateUserDto {
  @ApiProperty({ example: 'karlosagreda@hotmail.com', description: 'Email' })
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: '123456', description: 'Password' })
  @IsString()
  @IsNotEmpty()
  @Length(6, 20, {
    message: 'La contraseña debe tener entre 6 y 20 caracteres.',
  })
  password: string;

  tokenNotifications: string;
}
