import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgetPasswordDto {
  @ApiProperty({ example: 'karlosagreda@hotmail.com', description: 'Email' })
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty({ message: 'Introduce un Correo electrónico.' })
  email: string;
}
