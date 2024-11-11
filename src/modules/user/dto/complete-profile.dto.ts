import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CompleteProfileDto {
  @ApiProperty({ example: 'Jose', description: 'Nombre' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un nombre. ' })
  first_name: string;

  @ApiProperty({ example: 'Agreda', description: 'Apellido' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un apellido. ' })
  last_name: string;

  @ApiProperty({ example: '1123456789' })
  @IsNotEmpty({ message: 'Introduce un numero telefonico. ' })
  phone: string;

  @ApiProperty({ example: '2024/01/01' })
  @IsNotEmpty({ message: 'Introduce una fecha de de nacimiento. ' })
  date: Date;
}
