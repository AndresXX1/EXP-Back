import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class AddressDto {
  @ApiProperty({ example: 'Azcuénaga', description: 'Calle de la dirección' })
  @IsNotEmpty({ message: 'Introduce una calle.' })
  @IsString()
  street: string;

  @ApiProperty({ example: 1064, description: 'Altura de la dirección' })
  @IsNotEmpty({ message: 'Introduce la altura.' })
  @IsNumber()
  number: number;

  @ApiProperty({ example: 'B1638BBT', description: 'Código postal' })
  @IsNotEmpty({ message: 'Introduce un código postal.' })
  @IsString()
  zipCode: string;

  @ApiProperty({ example: 'Vicente Lopez', description: 'Ciudad' })
  @IsNotEmpty({ message: 'Introduce una ciudad.' })
  @IsString()
  city: string;

  @ApiProperty({ example: 'Buenos Aires', description: 'Provincia' })
  @IsNotEmpty({ message: 'Introduce una provincia.' })
  @IsString()
  province: string;
}
