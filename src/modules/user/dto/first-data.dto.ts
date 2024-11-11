import { IsNotEmpty, IsString, IsNumberString, Length, MinLength, MaxLength, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateFirstDataDto {
  @ApiProperty({ example: 'Jose', description: 'Nombre' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un nombre.' })
  @MinLength(3, { message: 'El nombre debe tener al menos 3 caracteres.' })
  @MaxLength(28, { message: 'El nombre no debe exceder los 28 caracteres.' })
  @Matches(/^\S.*\S$|^\S$/, { message: 'El nombre no puede tener espacios al inicio o al final.' })
  first_name: string;

  @ApiProperty({ example: 'Agreda', description: 'Apellido' })
  @IsString()
  @IsNotEmpty({ message: 'Introduce un apellido.' })
  @MinLength(3, { message: 'El apellido debe tener al menos 3 caracteres.' })
  @MaxLength(28, { message: 'El apellido no debe exceder los 28 caracteres.' })
  @Matches(/^\S.*\S$|^\S$/, { message: 'El apellido no puede tener espacios al inicio o al final.' })
  last_name: string;

  @ApiProperty({ example: '20123456789', description: 'CUIL' })
  @IsNumberString({ no_symbols: true }, { message: 'El CUIL debe contener solo números.' })
  @Length(11, 11, { message: 'El CUIL debe tener 11 dígitos.' })
  @IsNotEmpty({ message: 'Introduce un número de CUIL.' })
  cuil: string;
}
