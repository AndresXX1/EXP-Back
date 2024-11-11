import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateAdminDto {
  @ApiProperty({ example: 'joseleonardoagreda@gmail.com', description: 'Email' })
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty({ message: 'Introduce un Correo electrónico.' })
  email: string;

  @ApiProperty({ example: '123456', description: 'Password' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce una Contraseña.' })
  @Length(6, 20, {
    message: 'La contraseña debe tener entre 6 y 20 caracteres.',
  })
  password: string;

  @ApiProperty({ example: 'Jose Agreda', description: 'Nombre completo' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un Nombre completo.' })
  @Length(3, undefined, {
    message: 'El nombre debe tener al menos 3 caracteres.',
  })
  full_name: string;

  @ApiProperty({ example: 'default-user-avatar.png' })
  @IsString()
  avatar?: string;
}
