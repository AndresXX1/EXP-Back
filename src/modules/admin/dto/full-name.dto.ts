import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class FullNameDto {
  @ApiProperty({ example: 'Jose', description: 'Nombre completo' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un nombre. ' })
  full_name: string;
}
