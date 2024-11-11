import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class PasswordDto {
  @ApiProperty({ example: '123456', description: 'vieja password' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un vieja contraseña.' })
  password: string;

  @ApiProperty({ example: '123456', description: 'nueva password' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un nueva contraseña.' })
  new_password: string;
}
